import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { Webhook } from 'svix';
import { createClient } from '@supabase/supabase-js';
import CryptoJS from 'crypto-js';

const app = express();
const PORT = process.env.PORT || 5000;
const ENC_KEY = process.env.ENCRYPTION_KEY;

if (!ENC_KEY) { console.error('FATAL: ENCRYPTION_KEY missing'); }

const supabase1 = createClient(process.env.SUPABASE_URL_1, process.env.SUPABASE_KEY_1);
const supabase2 = createClient(process.env.SUPABASE_URL_2, process.env.SUPABASE_KEY_2);

function encrypt(data) {
  return CryptoJS.AES.encrypt(JSON.stringify(data), ENC_KEY).toString();
}
function decrypt(ciphertext) {
  const bytes = CryptoJS.AES.decrypt(ciphertext, ENC_KEY);
  return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
}

function secureClient(req, res, next) {
  const header = req.headers['x-rm-secure-lock'];
  if (header !== 'activated-mdm-client') {
    return res.status(403).json({ error: 'Forbidden: Invalid security header.' });
  }
  next();
}

function decryptBody(req, res, next) {
  try {
    console.log(`\n========================================`);
    console.log(`⚡ [API HIT] : ${req.method} ${req.originalUrl}`);

    if (req.body && req.body.payload) {
      req.decrypted = decrypt(req.body.payload);
    }
    next();
  } catch (e) {
    console.error(`❌ [DECRYPTION FAILED]: Invalid payload at ${req.originalUrl}`);
    return res.status(400).json({ error: 'Decryption failed. Check Keys.' });
  }
}

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'x-rm-secure-lock'] }));
app.use('/api/webhook/clerk', express.raw({ type: 'application/json' }));

// 🔥 FIX: 50MB limit taake Photos ki Base64 string block na ho!
app.use(express.json({ limit: '50mb' })); 

async function generateUniqueUID() {
  let uid, exists;
  do {
    uid = Math.floor(100000000 + Math.random() * 900000000).toString();
    const { data } = await supabase1.from('users').select('uid').eq('uid', uid);
    exists = data && data.length > 0;
  } while (exists);
  return uid;
}

app.post('/api/webhook/clerk', async (req, res) => {
  const webhookSecret = process.env.CLERK_WEBHOOK_SECRET;
  const wh = new Webhook(webhookSecret);
  let evt;
  try {
    evt = wh.verify(req.body, { 'svix-id': req.headers['svix-id'], 'svix-timestamp': req.headers['svix-timestamp'], 'svix-signature': req.headers['svix-signature'] });
  } catch (err) { return res.status(400).json({ error: 'Invalid webhook' }); }

  if (evt.type === 'user.created') {
    const { id: clerkId, email_addresses, first_name, last_name } = evt.data;
    const email = email_addresses[0]?.email_address || '';
    const { data: existing } = await supabase1.from('users').select('uid').eq('clerk_id', clerkId).single();
    if (existing) return res.json({ ok: true });

    try {
      const uid = await generateUniqueUID();
      await supabase1.from('users').insert({ clerk_id: clerkId, email, first_name: first_name || '', last_name: last_name || '', uid, activated: false, created_at: new Date().toISOString() });
    } catch (e) {}
  }
  res.status(200).json({ received: true });
});

app.post('/api/uid', secureClient, decryptBody, async (req, res) => {
  const { clerkId } = req.decrypted;
  if (!clerkId) return res.status(400).json({ error: 'Missing clerkId' });

  let { data, error } = await supabase1.from('users').select('uid, email, first_name, last_name, activated').eq('clerk_id', clerkId).single();

  if (error || !data) {
    const newUid = await generateUniqueUID();
    await supabase1.from('users').insert({ clerk_id: clerkId, email: 'operator@rmmdm.io', first_name: 'Operator', uid: newUid, activated: false, created_at: new Date().toISOString() });
    data = { uid: newUid, email: 'operator@rmmdm.io', first_name: 'Operator', last_name: '', activated: false };
  }
  res.json({ payload: encrypt({ uid: data.uid, email: data.email, firstName: data.first_name, lastName: data.last_name, activated: data.activated }) });
});

const STEP_MIN_MS = 5000;
app.post('/api/activation/init', secureClient, decryptBody, async (req, res) => {
  const { clerkId } = req.decrypted;
  const { data } = await supabase1.from('users').select('uid, activated').eq('clerk_id', clerkId).single();
  if (!data) return res.status(404).json({ error: 'User not found' });
  const token = encrypt({ step: 1, timestamp: Date.now(), uid: data.uid, clerkId });
  res.json({ payload: encrypt({ token, step: 1, alreadyActivated: data.activated }) });
});

app.post('/api/activation/step', secureClient, decryptBody, async (req, res) => {
  const { token, nextStep } = req.decrypted;
  let prev;
  try { prev = decrypt(token); } catch { return res.status(400).json({ error: 'Invalid token' }); }
  if (Date.now() - prev.timestamp < STEP_MIN_MS) return res.status(429).json({ error: `Wait ${Math.ceil((STEP_MIN_MS - (Date.now() - prev.timestamp)) / 1000)}s` });
  if (nextStep !== prev.step + 1 || nextStep > 5) return res.status(400).json({ error: 'Invalid step' });

  const newToken = encrypt({ step: nextStep, timestamp: Date.now(), uid: prev.uid, clerkId: prev.clerkId });
  if (nextStep === 5) {
    await supabase1.from('users').update({ activated: true, activated_at: new Date().toISOString() }).eq('clerk_id', prev.clerkId);
    return res.json({ payload: encrypt({ complete: true, uid: prev.uid }) });
  }
  res.json({ payload: encrypt({ token: newToken, step: nextStep }) });
});

// 🔥 DASHBOARD: ADD COMMAND (WITH OFFLINE PROTECTION)
app.post('/api/device/command', secureClient, decryptBody, async (req, res) => {
  const { uid, command, params } = req.decrypted;
  if (!uid || !command) return res.status(400).json({ error: 'Missing uid/command' });

  // 1. Check if device is actually online
  const { data: statusData } = await supabase2.from('device_status').select('updated_at, online').eq('uid', uid).single();
  let isOnline = statusData?.online || false;
  if (statusData && statusData.updated_at) {
    const diff = Date.now() - new Date(statusData.updated_at).getTime();
    if (diff > 35000) { isOnline = false; } // Agar 35 second se ping nahi aya toh offline
  }

  // 2. Agar offline hai toh Dashboard ko Error bhej do (Pending mein nahi jayegi)
  if (!isOnline) {
    return res.status(400).json({ error: 'Target device is currently offline. Signal aborted.' });
  }

  // 3. Agar online hai toh queue mein daal do
  const { data, error } = await supabase2.from('commands').insert({
    uid, command, params: params || {}, status: 'pending', created_at: new Date().toISOString(),
  }).select().single();
  if (error) return res.status(500).json({ error: 'Queue failed' });
  res.json({ payload: encrypt({ success: true, commandId: data.id }) });
});

app.post('/api/device/commands', secureClient, decryptBody, async (req, res) => {
  const { uid } = req.decrypted;
  const { data } = await supabase2.from('commands').select('*').eq('uid', uid).eq('status', 'pending').order('created_at', { ascending: true }).limit(5);
  if (data && data.length > 0) {
    const ids = data.map(cmd => cmd.id);
    await supabase2.from('commands').update({ status: 'processing' }).in('id', ids);
  }
  res.json({ payload: encrypt({ commands: data || [] }) });
});

app.post('/api/device/logs', secureClient, decryptBody, async (req, res) => {
  const { uid, event, command, status, data } = req.decrypted;
  if (event) {
    await supabase2.from('logs').insert({ uid, event, command, status, data: data || {}, created_at: new Date().toISOString() });
    if (command && status) {
      await supabase2.from('commands').update({ status }).eq('uid', uid).eq('command', command).eq('status', 'processing');
    }
    return res.json({ payload: encrypt({ success: true }) });
  }
  const { data: dbData } = await supabase2.from('logs').select('*').eq('uid', uid).order('created_at', { ascending: false }).limit(50);
  res.json({ payload: encrypt({ logs: dbData || [] }) });
});

app.post('/api/device/status', secureClient, decryptBody, async (req, res) => {
  const { uid, battery, online, model, os_version } = req.decrypted;
  if (battery !== undefined) {
    await supabase2.from('device_status').upsert({ uid, battery, online: online !== undefined ? online : true, model, os_version, updated_at: new Date().toISOString() }, { onConflict: 'uid' });
    return res.json({ payload: encrypt({ success: true }) });
  }
  const { data } = await supabase2.from('device_status').select('*').eq('uid', uid).single();
  let isActuallyOnline = data?.online || false;
  if (data && data.updated_at) {
    const diff = Date.now() - new Date(data.updated_at).getTime();
    if (diff > 35000) { isActuallyOnline = false; }
  }
  const finalStatus = data ? { ...data, online: isActuallyOnline } : { battery: null, online: false, updated_at: null };
  res.json({ payload: encrypt({ status: finalStatus }) });
});

app.get('/', (req, res) => res.send('RM-MDM Backend is LIVE! 🚀'));
app.listen(PORT, () => console.log(`🚀 Server on :${PORT}`));
export default app;
