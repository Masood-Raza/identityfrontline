const { app } = require('@azure/functions');
const { sign, verify } = require('../shared/token');
const { subscribersTable } = require('../shared/storage');

const SESSION_TTL_MS = 180 * 24 * 60 * 60 * 1000;

app.http('verify', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'verify',
  handler: async (request, context) => {
    const defaultRedirect = `${process.env.SITE_URL || 'https://identityfrontline.com'}/jobs.html`;
    const redirect = request.query.get('redirect') || defaultRedirect;
    const token = request.query.get('token') || '';

    const payload = verify(token);
    if (!payload || payload.purpose !== 'verify' || !payload.email) {
      return redirectTo(`${redirect}?verify=expired`);
    }

    const email = payload.email;
    try {
      await subscribersTable().upsertEntity(
        {
          partitionKey: 'subscriber',
          rowKey: encodeURIComponent(email),
          email,
          verified: true,
          verifiedAt: new Date().toISOString()
        },
        'Merge'
      );
    } catch (err) {
      context.error('verify: table upsert failed', err);
      return redirectTo(`${redirect}?verify=error`);
    }

    const sessionToken = sign({ email, purpose: 'session', exp: Date.now() + SESSION_TTL_MS });
    return redirectTo(`${redirect}?verified=${encodeURIComponent(sessionToken)}`);
  }
});

function redirectTo(location) {
  return { status: 302, headers: { Location: location } };
}
