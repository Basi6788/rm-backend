'use strict';
const express = require('express');
const cors = require('cors');
require('dotenv').config();
const { Webhook } = require('svix');
const { createClient } = require('@supabase/supabase-js');
const CryptoJS = require('crypto-js');

const app = express();
const PORT = process.env.PORT || 5000;
const ENC_KEY = process.env.ENCRYPTION_KEY;

if (!ENC_KEY) { console.error('FATAL: ENCRYPTION_KEY missing'); process.exit(1); }

// ── Supabase ──────────────────────────────────────────────────
const sb1 = createClient(process.env.SUPABASE_URL_1, process.env.SUPABASE_KEY_1);
const sb2 = createClient(process.env.SUPABASE_URL_2, process.env.SUPABASE_KEY_2);

// ── Crypto helpers (CJS — no ESM issues) ─────────────────────
function encrypt(obj) {
  try {
    return CryptoJS.AES.encrypt(JSON.stringify(obj), ENC_KEY).toString();
  } catch (e) {
    console.error('[ENCRYPT ERROR]', e.message);
    throw e;
  }
}

function decrypt(cipher) {
  try {
    const bytes = CryptoJS.AES.decrypt(cipher, ENC_KEY);
    const str = bytes.toString(CryptoJS.enc.Utf8);
    if (!str) throw new Error('Empty decrypted string');
    return JSON.parse(str);
  } catch (e) {
    console.error('[DECRYPT ERROR]', e.message, '| cipher prefix:', cipher ? cipher.slice(0, 30) : 'null');
    throw e;
  }
}

// ── Middlewares ───────────────────────────────────────────────
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','x-rm-secure-lock'] }));
app.use('/api/webhook/clerk', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '2mb' }));

// Debug logger
app.use((req, res, next) => {
  if (req.path !== '/api/webhook/clerk') {
    const bodyString = req.body ? JSON.stringify(req.body) : '';
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`, bodyString.slice(0, 120));
  }
  next();
});

function guard(req, res, next) {
  if (req.headers['x-rm-secure-lock'] !== 'activated-mdm-client') {
    return res.status(403).json({ error: 'Forbidden: bad security header' });
  }
  next();
}

function parseBody(req, res, next) {
  if (!req.body || !req.body.payload) {
    return res.status(400).json({ error: 'Missing payload field' });
  }
  try {
    req.data = decrypt(req.body.payload);
    next();
  } catch (e) {
    console.error('[DECRYPTION FAILED]: Invalid payload at', req.path);
    return res.status(400).json({ error: 'Decryption failed. Key mismatch?' });
  }
}

// ── Health check ──────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'RM-MDM Backend v2.0 Online', ts: Date.now() }));
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ── UID generator ─────────────────────────────────────────────
async function genUID() {
  let uid, exists;
  do {
    uid = String(Math.floor(100000000 + Math.random() * 900000000));
    const { data } = await sb1.from('users').select('uid').eq('uid', uid);
    exists = data && data.length > 0;
  } while (exists);
  return uid;
}

// ── CLERK WEBHOOK ─────────────────────────────────────────────
app.post('/api/webhook/clerk', async (req, res) => {
  let evt;
  try {
    const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET);
    evt = wh.verify(req.body, {
      'svix-id': req.headers['svix-id'],
      'svix-timestamp': req.headers['svix-timestamp'],
      'svix-signature': req.headers['svix-signature'],
    });
  } catch (e) {
    console.error('Webhook verify fail:', e.message);
    return res.status(400).json({ error: 'Invalid webhook' });
  }

  if (evt.type === 'user.created') {
    const { id: clerkId, email_addresses, first_name, last_name } = evt.data;
    const email = email_addresses[0]?.email_address || '';
    const { data: existing } = await sb1.from('users').select('uid').eq('clerk_id', clerkId).single();
    if (existing) { console.log('User already exists:', clerkId); return res.json({ ok: true }); }
    try {
      const uid = await genUID();
      const { error } = await sb1.from('users').insert({ clerk_id: clerkId, email, first_name: first_name || '', last_name: last_name || '', uid, activated: false, created_at: new Date().toISOString() });
      if (error) { console.error('Insert error:', error); return res.status(500).json({ error: 'DB error' }); }
      console.log(`✅ Created user ${email} → UID ${uid}`);
    } catch (e) {
      console.error('genUID error:', e);
      return res.status(500).json({ error: 'UID gen failed' });
    }
  }
  res.json({ received: true });
});

// ── GET / CREATE UID ──────────────────────────────────────────
app.post('/api/uid', guard, parseBody, async (req, res) => {
  const { clerkId, email, firstName, lastName } = req.data;
  if (!clerkId) return res.status(400).json({ error: 'Missing clerkId' });

  let { data, error } = await sb1.from('users').select('uid,email,first_name,last_name,activated').eq('clerk_id', clerkId).single();

  if (!data || error) {
    console.log(`User not found in DB, auto-creating for clerkId=${clerkId}`);
    try {
      const uid = await genUID();
      const ins = await sb1.from('users').insert({
        clerk_id: clerkId, email: email || '', first_name: firstName || '', last_name: lastName || '', uid, activated: false, created_at: new Date().toISOString()
      }).select().single();
      if (ins.error) { return res.status(500).json({ error: 'DB insert failed' }); }
      data = ins.data;
    } catch (e) {
      return res.status(500).json({ error: 'Failed to create user record' });
    }
  }
  res.json({ payload: encrypt({ uid: data.uid, email: data.email, firstName: data.first_name, lastName: data.last_name, activated: data.activated }) });
});

// ── ACTIVATION INIT ───────────────────────────────────────────
app.post('/api/activation/init', guard, parseBody, async (req, res) => {
  const { clerkId } = req.data;
  if (!clerkId) return res.status(400).json({ error: 'Missing clerkId' });
  const { data } = await sb1.from('users').select('uid,activated').eq('clerk_id', clerkId).single();
  if (!data) return res.status(404).json({ error: 'User not found.' });
  const token = encrypt({ step: 1, ts: Date.now(), uid: data.uid, clerkId });
  res.json({ payload: encrypt({ token, step: 1, uid: data.uid, alreadyActivated: data.activated }) });
});

// ── ACTIVATION STEP ───────────────────────────────────────────
app.post('/api/activation/step', guard, parseBody, async (req, res) => {
  const { token, nextStep } = req.data;
  if (!token || !nextStep) return res.status(400).json({ error: 'Missing fields' });
  let prev;
  try { prev = decrypt(token); } catch { return res.status(400).json({ error: 'Invalid token' }); }

  const elapsed = Date.now() - prev.ts;
  if (elapsed < 4800) return res.status(429).json({ error: `Too fast! Wait ${Math.ceil((5000 - elapsed)/1000)}s` });
  if (nextStep !== prev.step + 1 || nextStep > 5) return res.status(400).json({ error: 'Invalid sequence' });

  if (nextStep === 5) {
    await sb1.from('users').update({ activated: true, activated_at: new Date().toISOString() }).eq('clerk_id', prev.clerkId);
    return res.json({ payload: encrypt({ complete: true, uid: prev.uid }) });
  }
  res.json({ payload: encrypt({ token: encrypt({ step: nextStep, ts: Date.now(), uid: prev.uid, clerkId: prev.clerkId }), step: nextStep }) });
});

// ── DASHBOARD: ADD COMMAND TO QUEUE ───────────────────────────
app.post('/api/device/command', guard, parseBody, async (req, res) => {
  const { uid, command, params } = req.data;
  if (!uid || !command) return res.status(400).json({ error: 'Missing uid/command' });
  const { data, error } = await sb2.from('commands').insert({ uid, command, params: params || {}, status: 'pending', created_at: new Date().toISOString() }).select().single();
  if (error) return res.status(500).json({ error: 'Queue failed' });
  res.json({ payload: encrypt({ success: true, commandId: data.id }) });
});

// ── MOBILE: FETCH COMMANDS QUEUE ──────────────────────────────
app.post('/api/device/commands', guard, parseBody, async (req, res) => {
  const { uid } = req.data;
  if (!uid) return res.status(400).json({ error: 'Missing uid' });
  
  // Mobile app pending commands nikal raha hai
  const { data } = await sb2.from('commands').select('*').eq('uid', uid).eq('status', 'pending').order('created_at', { ascending: true }).limit(5);
  
  // Agar commands mili hain, toh inko 'processing' kar do taake baar baar execute na hon
  if (data && data.length > 0) {
    const ids = data.map(cmd => cmd.id);
    await sb2.from('commands').update({ status: 'processing' }).in('id', ids);
  }
  
  res.json({ payload: encrypt({ commands: data || [] }) });
});

// ── LOGS: INSERT (APP) OR FETCH (DASHBOARD) ───────────────────
app.post('/api/device/logs', guard, parseBody, async (req, res) => {
  const { uid, event, command, status } = req.data;
  if (!uid) return res.status(400).json({ error: 'Missing uid' });

  // Agar 'event' mojood hai toh matlab Mobile App log insert kar rahi hai
  if (event) {
    await sb2.from('logs').insert({ uid, event, command, status, created_at: new Date().toISOString() });
    // Command ka status bhi update kardo table mein
    if (command && status) {
      await sb2.from('commands').update({ status }).eq('uid', uid).eq('command', command).eq('status', 'processing');
    }
    return res.json({ payload: encrypt({ success: true }) });
  }

  // Warna Dashboard logs mang raha hai
  const { data } = await sb2.from('logs').select('*').eq('uid', uid).order('created_at', { ascending: false }).limit(50);
  res.json({ payload: encrypt({ logs: data || [] }) });
});

// ── STATUS: UPSERT (APP) OR FETCH (DASHBOARD) ─────────────────
app.post('/api/device/status', guard, parseBody, async (req, res) => {
  const { uid, battery, online } = req.data;
  if (!uid) return res.status(400).json({ error: 'Missing uid' });

  // Agar battery/online hai toh matlab Mobile App status update kar rahi hai
  if (battery !== undefined) {
    const { error } = await sb2.from('device_status').upsert({
      uid,
      battery,
      online: online !== undefined ? online : true,
      updated_at: new Date().toISOString()
    }, { onConflict: 'uid' });
    
    if (error) console.error("Upsert Error:", error);
    return res.json({ payload: encrypt({ success: true }) });
  }

  // Warna Dashboard status mang raha hai
  const { data } = await sb2.from('device_status').select('*').eq('uid', uid).single();
  
  // Auto-Offline Checker: Agar 35 seconds se phone ne ping nahi kiya toh OFFLINE dikhao
  let isActuallyOnline = data?.online || false;
  if (data && data.updated_at) {
    const diff = Date.now() - new Date(data.updated_at).getTime();
    if (diff > 35000) { isActuallyOnline = false; }
  }

  const finalStatus = data ? { ...data, online: isActuallyOnline } : { battery: null, online: false, updated_at: null };
  res.json({ payload: encrypt({ status: finalStatus }) });
});

app.listen(PORT, () => console.log(`🚀 RM-MDM Backend v2 on :${PORT}`));

// VERCEL EXPORT (Zaroori Hai!)
module.exports = app;

