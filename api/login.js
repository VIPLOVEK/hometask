import crypto from 'crypto';

function createToken(user, secret) {
  const payload = Buffer.from(JSON.stringify({
    user,
    exp: Date.now() + 30 * 24 * 60 * 60 * 1000,
    iat: Date.now(),
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

export default async function handler(req, res) {
  const origin = req.headers.origin;
  const allowed = process.env.ALLOWED_ORIGIN || '';
  if (allowed && origin === allowed) {
    res.setHeader('Access-Control-Allow-Origin', allowed);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: 'Invalid JSON' }); }
  }

  const { username, password } = body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const users = [
    { name: process.env.USER1_NAME, pass: process.env.USER1_PASS },
    { name: process.env.USER2_NAME, pass: process.env.USER2_PASS },
  ].filter(u => u.name && u.pass);

  if (users.length === 0) {
    return res.status(500).json({ error: 'Server not configured — set USER1_NAME, USER1_PASS, USER2_NAME, USER2_PASS env vars' });
  }

  const secret = process.env.SESSION_SECRET;
  if (!secret) {
    return res.status(500).json({ error: 'Server not configured — set SESSION_SECRET env var' });
  }

  // Constant-time comparison to avoid timing attacks
  const match = users.find(u =>
    u.name.toLowerCase() === username.toLowerCase() &&
    u.pass.length === password.length &&
    crypto.timingSafeEqual(Buffer.from(u.pass), Buffer.from(password))
  );

  if (!match) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = createToken(match.name, secret);
  return res.status(200).json({ token, user: match.name });
}
