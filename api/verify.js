import crypto from 'crypto';

function verifyToken(token, secret) {
  if (!token || !token.includes('.')) return null;
  const dot = token.lastIndexOf('.');
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  // Constant-time compare
  try {
    if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) return null;
  } catch { return null; }
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch { return null; }
}

export default function handler(req, res) {
  const origin = req.headers.origin;
  const allowed = process.env.ALLOWED_ORIGIN || '';
  if (allowed && origin === allowed) {
    res.setHeader('Access-Control-Allow-Origin', allowed);
  }
  res.setHeader('Vary', 'Origin');

  const token = req.query.token || req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  const secret = process.env.SESSION_SECRET;
  if (!secret) return res.status(500).json({ error: 'Server not configured' });

  const payload = verifyToken(token, secret);
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token' });

  return res.status(200).json({ user: payload.user, exp: payload.exp });
}
