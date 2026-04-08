import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { Webhook } from 'svix';
import { createClient } from '@supabase/supabase-js';
import CryptoJS from 'crypto-js';

const app = express();
const PORT = process.env.PORT || 5000;
const ENC_KEY = process.env.ENCRYPTION_KEY;

// ── Supabase clients ──────────────────────────────────────────
const supabase1 = createClient(process.env.SUPABASE_URL_1, process.env.SUPABASE_KEY_1);
const supabase2 = createClient(process.env.SUPABASE_URL_2, process.env.SUPABASE_KEY_2);

// ── Encryption helpers (WITH LIVE TERMINAL LOGS) ───────────────
function encrypt(data) {
  console.log(`📤 [OUTGOING PAYLOAD] (Data to be encrypted before sending):\n`, JSON.stringify(data, null, 2), `\n----------------------------------------\n`);
  return CryptoJS.AES.encrypt(JSON.stringify(data), ENC_KEY).toString();
}

function decrypt(ciphertext) {
  const bytes = CryptoJS.AES.decrypt(ciphertext, ENC_KEY);
  return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
}

// ── Security middleware ───────────────────────────────────────
function secureClient(req, res, next) {
  const header = req.headers['x-rm-secure-lock'];
  if (header !== 'activated-mdm-client') {
    console.log(`🚫 [BLOCKED]: Invalid Security Header attempted at ${req.originalUrl}`);
    return res.status(403).json({ error: 'Forbidden: Invalid security header.' });
  }
  next();
}

// ── Decrypt body middleware (WITH LIVE TERMINAL LOGS) ──────────
function decryptBody(req, res, next) {
  try {
    if (req.body && req.body.payload) {
      req.decrypted = decrypt(req.body.payload);
      console.log(`\n========================================`);
      console.log(`⚡ [API HIT] : ${req.method} ${req.originalUrl}`);
      console.log(`🔓 [INCOMING DECRYPTED PAYLOAD]:\n`, JSON.stringify(req.decrypted, null, 2));
    } else {
      console.log(`\n========================================`);
      console.log(`⚡ [API HIT] : ${req.method} ${req.originalUrl} (No Encrypted Payload Found)`);
    }
    next();
  } catch (e) {
    console.error(`❌ [DECRYPTION FAILED]: Invalid payload at ${req.originalUrl}`);
    return res.status(400).json({ error: 'Decryption failed.' });
  }
}

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'x-rm-secure-lock'],
}));

// Raw body for Clerk webhook
app.use('/api/webhook/clerk', express.raw({ type: 'application/json' }));
app.use(express.json());

// ── UID Generator ─────────────────────────────────────────────
async function generateUniqueUID() {
  let uid, exists;
  do {
    uid = Math.floor(100000000 + Math.random() * 900000000).toString();
    const { data } = await supabase1.from('users').select('uid').eq('uid', uid);
    exists = data && data.length > 0;
  } while (exists);
  return uid;
}

// ── CLERK WEBHOOK ─────────────────────────────────────────────
app.post('/api/webhook/clerk', async (req, res) => {
  const webhookSecret = process.env.CLERK_WEBHOOK_SECRET;
  const wh = new Webhook(webhookSecret);
  let evt;
  try {
    evt = wh.verify(req.body, {
      'svix-id': req.headers['svix-id'],
      'svix-timestamp': req.headers['svix-timestamp'],
      'svix-signature': req.headers['svix-signature'],
    });
  } catch (err) {
    console.error('❌ Webhook verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid webhook signature' });
  }

  if (evt.type === 'user.created') {
    const { id: clerkId, email_addresses, first_name, last_name } = evt.data;
    const email = email_addresses[0]?.email_address || '';
    try {
      const uid = await generateUniqueUID();
      const { error } = await supabase1.from('users').insert({
        clerk_id: clerkId,
        email,
        first_name: first_name || '',
        last_name: last_name || '',
        uid,
        created_at: new Date().toISOString(),
      });
      if (error) {
        console.error('❌ Supabase insert error:', error);
        return res.status(500).json({ error: 'DB insert failed' });
      }
      console.log(`✅ New user registered via Webhook: ${email} → Assigned UID: ${uid}`);
    } catch (e) {
      console.error('❌ Error creating user:', e);
      return res.status(500).json({ error: 'Server error' });
    }
  }
  res.status(200).json({ received: true });
});

// ── GET UID ───────────────────────────────────────────────────
app.post('/api/uid', secureClient, decryptBody, async (req, res) => {
  const { clerkId } = req.decrypted;
  if (!clerkId) return res.status(400).json({ error: 'Missing clerkId' });
  
  const { data, error } = await supabase1.from('users').select('uid, email, first_name, last_name').eq('clerk_id', clerkId).single();
  if (error || !data) {
      console.log(`⚠️ User not found in DB for ClerkID: ${clerkId}`);
      return res.status(404).json({ error: 'User not found' });
  }
  res.json({ payload: encrypt({ uid: data.uid, email: data.email, firstName: data.first_name, lastName: data.last_name }) });
});

// ── ACTIVATION — Step Validator ───────────────────────────────
const STEP_MIN_MS = 5000;

app.post('/api/activation/init', secureClient, decryptBody, async (req, res) => {
  const { clerkId } = req.decrypted;
  if (!clerkId) return res.status(400).json({ error: 'Missing clerkId' });
  
  const { data } = await supabase1.from('users').select('uid').eq('clerk_id', clerkId).single();
  if (!data) return res.status(404).json({ error: 'User not found' });
  
  const token = encrypt({ step: 1, timestamp: Date.now(), uid: data.uid, clerkId });
  res.json({ payload: encrypt({ token, step: 1 }) });
});

app.post('/api/activation/step', secureClient, decryptBody, async (req, res) => {
  const { token, nextStep } = req.decrypted;
  if (!token || !nextStep) return res.status(400).json({ error: 'Missing fields' });
  
  let prev;
  try { prev = decrypt(token); } catch { return res.status(400).json({ error: 'Invalid token' }); }
  
  const elapsed = Date.now() - prev.timestamp;
  if (elapsed < STEP_MIN_MS) {
    console.log(`🤖 BOT DETECTED: Step ${nextStep} attempted too fast (${elapsed}ms)`);
    return res.status(429).json({ error: `Too fast. Wait ${Math.ceil((STEP_MIN_MS - elapsed) / 1000)}s more.` });
  }
  
  if (nextStep !== prev.step + 1) {
    console.log(`⚠️ Invalid step sequence: Expected ${prev.step + 1}, got ${nextStep}`);
    return res.status(400).json({ error: 'Invalid step sequence' });
  }
  
  if (nextStep > 5) return res.status(400).json({ error: 'Already complete' });
  
  const newToken = encrypt({ step: nextStep, timestamp: Date.now(), uid: prev.uid, clerkId: prev.clerkId });
  
  if (nextStep === 5) {
    await supabase1.from('users').update({ activated: true, activated_at: new Date().toISOString() }).eq('clerk_id', prev.clerkId);
    console.log(`🎉 Protocol Activated for UID: ${prev.uid}`);
    return res.json({ payload: encrypt({ complete: true, uid: prev.uid }) });
  }
  
  res.json({ payload: encrypt({ token: newToken, step: nextStep }) });
});

// ── DEVICE COMMANDS ───────────────────────────────────────────
app.post('/api/device/command', secureClient, decryptBody, async (req, res) => {
  const { uid, command, params } = req.decrypted;
  if (!uid || !command) return res.status(400).json({ error: 'Missing uid or command' });
  
  const { data, error } = await supabase2.from('commands').insert({
    uid,
    command,
    params: params || {},
    status: 'pending',
    created_at: new Date().toISOString(),
  }).select().single();
  
  if (error) {
    console.error('❌ Command insert error:', error);
    return res.status(500).json({ error: 'Failed to queue command' });
  }
  res.json({ payload: encrypt({ success: true, commandId: data.id }) });
});

app.post('/api/device/logs', secureClient, decryptBody, async (req, res) => {
  const { uid } = req.decrypted;
  if (!uid) return res.status(400).json({ error: 'Missing uid' });
  
  const { data, error } = await supabase2.from('logs').select('*').eq('uid', uid).order('created_at', { ascending: false }).limit(50);
  if (error) {
      console.error('❌ Fetch logs error:', error);
      return res.status(500).json({ error: 'Failed to fetch logs' });
  }
  res.json({ payload: encrypt({ logs: data || [] }) });
});

app.post('/api/device/status', secureClient, decryptBody, async (req, res) => {
  const { uid } = req.decrypted;
  if (!uid) return res.status(400).json({ error: 'Missing uid' });
  
  const { data } = await supabase2.from('device_status').select('*').eq('uid', uid).single();
  res.json({ payload: encrypt({ status: data || { battery: null, online: false } }) });
});

// ── SERVER BOOT SEQUENCE & HEALTH CHECKS ──────────────────────
const bootServer = async () => {
    console.log("\n========================================");
    console.log("⏳ System Boot Sequence Initiated...");
    console.log("========================================\n");

    if (process.env.SUPABASE_URL_1 && process.env.SUPABASE_KEY_1) console.log("✅ [Supabase 1]: Auth & Users DB Connected! 👤");
    else console.log("❌ [Supabase 1]: Auth DB Credentials Missing! ⚠️");

    if (process.env.SUPABASE_URL_2 && process.env.SUPABASE_KEY_2) console.log("✅ [Supabase 2]: Device Logs DB Connected! 📱");
    else console.log("❌ [Supabase 2]: Device Logs DB Credentials Missing! ⚠️");

    if (process.env.CLERK_WEBHOOK_SECRET) console.log("✅ [Clerk Auth]: Webhook Secret Verified! 🔐");
    else console.log("❌ [Clerk Auth]: Webhook Secret Missing! ⚠️");

    if (process.env.ENCRYPTION_KEY) console.log("✅ [Security]  : AES-256 Encryption Active! 🛡️");
    else console.log("❌ [Security]  : Encryption Key Missing! System Vulnerable! ⚠️");

    app.listen(PORT, () => {
        console.log(`\n🚀 [Server]  : Live and running on http://localhost:${PORT}`);
        console.log(`⚡ [Status]  : MDM Master Backend Ready! 🥷\n`);
    });
};

bootServer();

