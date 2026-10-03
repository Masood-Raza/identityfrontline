const { TableClient } = require('@azure/data-tables');
const { BlobServiceClient } = require('@azure/storage-blob');

function connectionString() {
  const c = process.env.STORAGE_CONNECTION;
  if (!c) throw new Error('STORAGE_CONNECTION is not configured');
  return c;
}

function subscribersTable() {
  return TableClient.fromConnectionString(connectionString(), 'subscribers');
}

function applicationsTable() {
  return TableClient.fromConnectionString(connectionString(), 'applications');
}

function resumesContainer() {
  return BlobServiceClient.fromConnectionString(connectionString()).getContainerClient('resumes');
}

module.exports = { subscribersTable, applicationsTable, resumesContainer };
