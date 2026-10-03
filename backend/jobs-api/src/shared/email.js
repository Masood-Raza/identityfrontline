const { EmailClient } = require('@azure/communication-email');

// Lazily constructed: the connection string isn't available at module-load time
// in every context (e.g. local unit tests), so fail inside sendEmail() instead.
let client = null;
function getClient() {
  if (!client) {
    const conn = process.env.ACS_CONNECTION;
    if (!conn) throw new Error('Email is not configured yet: set ACS_CONNECTION on the Function App.');
    client = new EmailClient(conn);
  }
  return client;
}

async function sendEmail({ to, subject, html, text }) {
  const from = process.env.FROM_EMAIL;
  if (!from || from.startsWith('REPLACE_ME')) {
    throw new Error('Email is not configured yet: set FROM_EMAIL on the Function App.');
  }
  const poller = await getClient().beginSend({
    senderAddress: from,
    content: { subject, plainText: text, html },
    recipients: { to: [{ address: to }] }
  });
  const result = await poller.pollUntilDone();
  if (result.status !== 'Succeeded') {
    throw new Error(`Azure Communication Services send failed: ${result.status} ${JSON.stringify(result.error || {})}`);
  }
}

module.exports = { sendEmail };
