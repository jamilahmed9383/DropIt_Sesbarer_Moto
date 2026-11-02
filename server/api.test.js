import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));

async function freePort() {
  const server = createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

test('devices can consent to a verified file transfer and receiver acknowledgment completes it', async (t) => {
  const temp = await mkdtemp(path.join(os.tmpdir(), 'dropit-api-test-'));
  const port = await freePort();
  const child = spawn(process.execPath, ['api.js'], {
    cwd: here,
    env: { ...process.env, PORT: String(port), DATA_DIR: path.join(temp, 'data'), TRANSFER_DIR: path.join(temp, 'files') },
    stdio: 'ignore',
  });
  const base = `http://127.0.0.1:${port}`;
  t.after(async () => {
    child.kill();
    await rm(temp, { recursive: true, force: true });
  });

  let healthy = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    try { healthy = (await fetch(`${base}/health`)).ok; } catch { /* server is still starting */ }
    if (healthy) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(healthy, true, 'API should start');

  async function register(deviceId, name) {
    const response = await fetch(`${base}/api/devices/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ deviceId, name }),
    });
    assert.equal(response.status, 200);
    return (await response.json()).token;
  }
  const senderId = 'dev_sender_123456';
  const receiverId = 'dev_receiver_1234';
  const senderToken = await register(senderId, 'Sender');
  const receiverToken = await register(receiverId, 'Receiver');
  const headers = (id, token) => ({ 'X-Device-Id': id, 'X-Device-Token': token });

  const bytes = Buffer.from('DropIt integrity check ✓');
  const metadata = { name: 'hello world.txt', size: bytes.length, mimeType: 'text/plain', sha256: crypto.createHash('sha256').update(bytes).digest('hex') };
  const request = await fetch(`${base}/api/transfers/request`, {
    method: 'POST', headers: { ...headers(senderId, senderToken), 'content-type': 'application/json' },
    body: JSON.stringify({ receiverId, files: [metadata] }),
  });
  assert.equal(request.status, 201);
  const { transfer } = await request.json();
  assert.equal(transfer.status, 'pending');

  const accept = await fetch(`${base}/api/transfers/${transfer.id}/accept`, { method: 'POST', headers: headers(receiverId, receiverToken) });
  assert.equal(accept.status, 200);

  const form = new FormData();
  form.append('file', new Blob([bytes]), metadata.name);
  const upload = await fetch(`${base}/api/transfers/${transfer.id}/files/0`, {
    method: 'POST', headers: headers(senderId, senderToken), body: form,
  });
  assert.equal(upload.status, 200);
  assert.equal((await upload.json()).verified, true);
  const publicPath = await fetch(`${base}/uploads/transfers/${transfer.id}-0-private.bin`);
  assert.equal(publicPath.status, 404);

  const download = await fetch(`${base}/api/transfers/${transfer.id}/files/0`, { headers: headers(receiverId, receiverToken) });
  assert.equal(download.status, 200);
  assert.deepEqual(Buffer.from(await download.arrayBuffer()), bytes);

  const complete = await fetch(`${base}/api/transfers/${transfer.id}/complete`, { method: 'POST', headers: headers(receiverId, receiverToken) });
  assert.equal(complete.status, 200);
  assert.equal((await complete.json()).transfer.status, 'completed');

  const foreignRead = await fetch(`${base}/api/transfers/${transfer.id}/files/0`, { headers: headers('dev_other_123456', 'not-a-token') });
  assert.equal(foreignRead.status, 401);

  const declinedRequest = await fetch(`${base}/api/transfers/request`, {
    method: 'POST', headers: { ...headers(senderId, senderToken), 'content-type': 'application/json' },
    body: JSON.stringify({ receiverId, files: [metadata] }),
  });
  const declined = (await declinedRequest.json()).transfer;
  const decline = await fetch(`${base}/api/transfers/${declined.id}/reject`, { method: 'POST', headers: headers(receiverId, receiverToken) });
  assert.equal(decline.status, 200);
  const blockedUpload = await fetch(`${base}/api/transfers/${declined.id}/files/0`, {
    method: 'POST', headers: headers(senderId, senderToken), body: form,
  });
  assert.equal(blockedUpload.status, 409);
});
