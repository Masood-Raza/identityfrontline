// Plain HTTPS call to SendGrid's v3 Mail Send API via the Node 20+ global fetch,
// instead of pulling in @sendgrid/mail for one endpoint.
async function sendEmail({ to, subject, html, text }) {
  const apiKey = process.env.SENDGRID_API_KEY;
  const from = process.env.FROM_EMAIL;
  if (!apiKey || apiKey.startsWith('REPLACE_ME') || !from || from.startsWith('REPLACE_ME')) {
    throw new Error('Email is not configured yet: set SENDGRID_API_KEY and FROM_EMAIL on the Function App.');
  }
  const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: to }] }],
      from: { email: from, name: 'Identity Frontline' },
      subject,
      content: [
        { type: 'text/plain', value: text },
        { type: 'text/html', value: html }
      ]
    })
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`SendGrid send failed: ${res.status} ${body}`);
  }
}

module.exports = { sendEmail };
