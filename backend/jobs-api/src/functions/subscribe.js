const { app } = require('@azure/functions');
const { sign } = require('../shared/token');
const { sendEmail } = require('../shared/email');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const VERIFY_TTL_MS = 24 * 60 * 60 * 1000;

app.http('subscribe', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'subscribe',
  handler: async (request, context) => {
    let body;
    try {
      body = await request.json();
    } catch {
      return { status: 400, jsonBody: { error: 'Expected a JSON body.' } };
    }

    const email = String(body?.email || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email)) {
      return { status: 400, jsonBody: { error: 'Enter a valid email address.' } };
    }

    const siteUrl = process.env.SITE_URL || 'https://identityfrontline.com';
    const apiBase = `https://${request.headers.get('host')}`;
    const verifyToken = sign({ email, purpose: 'verify', exp: Date.now() + VERIFY_TTL_MS });
    const redirect = encodeURIComponent(`${siteUrl}/jobs.html`);
    const verifyLink = `${apiBase}/api/verify?token=${encodeURIComponent(verifyToken)}&redirect=${redirect}`;

    try {
      await sendEmail({
        to: email,
        subject: 'Confirm your subscription — Identity Frontline Jobs',
        text: `One click to unlock the Identity Frontline IAM job board:\n\n${verifyLink}\n\nThis link expires in 24 hours. If you didn't request this, ignore this email.`,
        html: `<p>One click to unlock the Identity Frontline IAM job board.</p>` +
          `<p><a href="${verifyLink}">Confirm your email →</a></p>` +
          `<p style="color:#888;font-size:12px">This link expires in 24 hours. If you didn't request this, ignore this email.</p>`
      });
    } catch (err) {
      context.error('subscribe: send failed', err);
      return { status: 503, jsonBody: { error: 'Could not send the verification email right now. Please try again shortly.' } };
    }

    return { status: 200, jsonBody: { ok: true } };
  }
});
