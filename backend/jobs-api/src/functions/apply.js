const { app } = require('@azure/functions');
const crypto = require('crypto');
const { verify } = require('../shared/token');
const { applicationsTable, resumesContainer } = require('../shared/storage');
const { sendEmail } = require('../shared/email');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_RESUME_BYTES = 8 * 1024 * 1024;
const ALLOWED_EXT = new Set(['.pdf', '.doc', '.docx']);

app.http('apply', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'apply',
  handler: async (request, context) => {
    let form;
    try {
      form = await request.formData();
    } catch {
      return { status: 400, jsonBody: { error: 'Expected multipart form data.' } };
    }

    const payload = verify(String(form.get('verifyToken') || ''));
    if (!payload || payload.purpose !== 'session' || !payload.email) {
      return { status: 401, jsonBody: { error: 'Please subscribe and verify your email before applying.' } };
    }

    const name = String(form.get('name') || '').trim();
    const email = String(form.get('email') || '').trim().toLowerCase();
    const job = String(form.get('job') || '').trim();
    const phone = String(form.get('phone') || '').trim();
    const linkedin = String(form.get('linkedin') || '').trim();
    const note = String(form.get('note') || '').trim();

    if (!name || !EMAIL_RE.test(email) || !job) {
      return { status: 400, jsonBody: { error: 'Name, a valid email, and a job are required.' } };
    }
    if (email !== payload.email) {
      return { status: 401, jsonBody: { error: 'Please apply using the same email address you verified.' } };
    }

    const resume = form.get('resume');
    if (!resume || typeof resume === 'string') {
      return { status: 400, jsonBody: { error: 'Attach a résumé (PDF or Word).' } };
    }
    const resumeName = resume.name || 'resume';
    const ext = (resumeName.match(/\.[a-zA-Z0-9]+$/) || [''])[0].toLowerCase();
    if (!ALLOWED_EXT.has(ext)) {
      return { status: 400, jsonBody: { error: 'Résumé must be a PDF or Word document.' } };
    }

    const buf = Buffer.from(await resume.arrayBuffer());
    if (buf.length === 0 || buf.length > MAX_RESUME_BYTES) {
      return { status: 400, jsonBody: { error: 'Résumé must be under 8MB.' } };
    }

    const id = crypto.randomUUID();
    const blobName = `${id}${ext}`;
    try {
      await resumesContainer().getBlockBlobClient(blobName).uploadData(buf, {
        blobHTTPHeaders: { blobContentType: resume.type || 'application/octet-stream' }
      });

      await applicationsTable().createEntity({
        partitionKey: 'application',
        rowKey: id,
        job,
        name,
        email,
        phone,
        linkedin,
        note,
        resumeBlob: blobName,
        resumeFileName: resumeName,
        submittedAt: new Date().toISOString()
      });
    } catch (err) {
      context.error('apply: storage write failed', err);
      return { status: 500, jsonBody: { error: 'Something went wrong saving your application. Please try again.' } };
    }

    // The application is already saved at this point regardless of whether the
    // notify email below succeeds, so a SendGrid hiccup never loses an applicant.
    const notifyTo = process.env.NOTIFY_EMAIL;
    if (notifyTo) {
      try {
        await sendEmail({
          to: notifyTo,
          subject: `New application: ${job}`,
          text: `${name} <${email}> applied for ${job}.\nPhone: ${phone || '-'}\nLinkedIn: ${linkedin || '-'}\nNote: ${note || '-'}\nResume stored as: ${blobName}`,
          html:
            `<p><b>${escapeHtml(name)}</b> &lt;${escapeHtml(email)}&gt; applied for <b>${escapeHtml(job)}</b>.</p>` +
            `<p>Phone: ${escapeHtml(phone) || '—'}<br>LinkedIn: ${escapeHtml(linkedin) || '—'}</p>` +
            `<p>${escapeHtml(note)}</p>` +
            `<p style="color:#888;font-size:12px">Résumé stored as ${blobName} in the resumes container.</p>`
        });
      } catch (err) {
        context.error('apply: notify email failed (application was still saved)', err);
      }
    }

    return { status: 200, jsonBody: { ok: true } };
  }
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
