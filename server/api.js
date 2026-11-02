import express from 'express';
import cors from 'cors';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const port = Number(process.env.PORT || 5000);
const maxFile = Number(process.env.MAX_FILE_BYTES || 5 * 1024 * 1024 * 1024);
const maxFiles = 50;
const dataDir = path.resolve(process.env.DATA_DIR || path.join(root, 'data'));
const transferDir = path.resolve(process.env.TRANSFER_DIR || path.join(root, 'uploads', 'transfers'));
const statePath = path.join(dataDir, 'state.json');
await fsp.mkdir(dataDir, { recursive: true });
await fsp.mkdir(transferDir, { recursive: true });
const state = { devices: {}, transfers: {} };
try {
  const disk = JSON.parse(await fsp.readFile(statePath, 'utf8'));
  state.devices = disk.devices || {};
  state.transfers = disk.transfers || {};
} catch (error) { if (error.code !== 'ENOENT') throw error; }
let writeQueue = Promise.resolve();
function save() {
  writeQueue = writeQueue.then(async () => {
    const temp = `${statePath}.tmp`;
    await fsp.writeFile(temp, JSON.stringify(state), { mode: 0o600 });
    await fsp.rename(temp, statePath);
  });
  return writeQueue;
}
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || true, allowedHeaders: ['Content-Type', 'X-Device-Id', 'X-Device-Token'] }));
app.use(express.json({ limit: '256kb' }));
app.use((req, _res, next) => { console.log(`${new Date().toISOString()} ${req.method} ${req.path}`); next(); });
app.use('/uploads/transfers', (_req, res) => error(res, 404, 'not_found', 'Transfer files are only available to authorized receivers.'));
app.use('/uploads', express.static(path.join(root, 'uploads'), { dotfiles: 'deny', index: false }));

function error(res, status, code, message) { return res.status(status).json({ success: false, error: { code, message } }); }
function validName(name) { return typeof name === 'string' && name.trim().length > 0 && name.length <= 180 && !/[\0\r\n]/.test(name); }
function equalSecret(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function authenticate(req, res, next) {
  const device = state.devices[req.get('X-Device-Id')];
  if (!device || !equalSecret(device.token, req.get('X-Device-Token'))) return error(res, 401, 'unauthorized', 'Register this device or register it again.');
  device.lastSeenAt = new Date().toISOString();
  req.device = device;
  next();
}
function view(t) {
  return { id: t.id, senderId: t.senderId, senderName: state.devices[t.senderId]?.name || 'DropIt device', receiverId: t.receiverId, receiverName: state.devices[t.receiverId]?.name || 'DropIt device', status: t.status, createdAt: t.createdAt, updatedAt: t.updatedAt, files: t.files.map(({ name, size, mimeType, sha256, uploaded, verified }) => ({ name, size, mimeType, sha256, uploaded, verified })) };
}
function getTransfer(req, res, who) {
  const t = state.transfers[req.params.transferId];
  if (!t) { error(res, 404, 'not_found', 'Transfer not found.'); return null; }
  const allowed = who === 'sender' ? t.senderId === req.device.id : who === 'receiver' ? t.receiverId === req.device.id : [t.senderId, t.receiverId].includes(req.device.id);
  if (!allowed) { error(res, 403, 'forbidden', 'This device is not part of the transfer.'); return null; }
  return t;
}

app.get('/health', (_req, res) => res.json({ status: 'OK', service: 'dropit', version: 2 }));
app.post('/api/devices/register', async (req, res, next) => {
  try {
    const { deviceId, name } = req.body || {};
    if (typeof deviceId !== 'string' || !/^[A-Za-z0-9_-]{8,80}$/.test(deviceId) || !validName(name)) return error(res, 400, 'invalid_device', 'A valid deviceId and device name are required.');
    const existing = state.devices[deviceId];
    if (existing) return error(res, 409, 'device_exists', 'This device ID is already registered. Clear the app data to create a new identity.');
    const token = crypto.randomBytes(32).toString('base64url');
    state.devices[deviceId] = { id: deviceId, name: name.trim(), token, createdAt: existing?.createdAt || new Date().toISOString(), lastSeenAt: new Date().toISOString() };
    await save();
    res.json({ success: true, device: { id: deviceId, name: name.trim() }, token });
  } catch (e) { next(e); }
});
app.get('/api/devices', authenticate, async (req, res, next) => {
  try {
    await save();
    const devices = Object.values(state.devices).filter((d) => d.id !== req.device.id && Date.now() - Date.parse(d.lastSeenAt) < 120000).map(({ id, name, lastSeenAt }) => ({ id, name, lastSeenAt }));
    res.json({ success: true, devices });
  } catch (e) { next(e); }
});
app.patch('/api/devices/me', authenticate, async (req, res, next) => {
  try {
    if (!validName(req.body?.name)) return error(res, 400, 'invalid_name', 'A device name is required.');
    req.device.name = req.body.name.trim(); await save();
    res.json({ success: true, device: { id: req.device.id, name: req.device.name } });
  } catch (e) { next(e); }
});
app.post('/api/transfers/request', authenticate, async (req, res, next) => {
  try {
    const { receiverId, files } = req.body || {};
    if (!state.devices[receiverId] || receiverId === req.device.id) return error(res, 400, 'invalid_receiver', 'Choose a registered receiver device.');
    if (!Array.isArray(files) || !files.length || files.length > maxFiles) return error(res, 400, 'invalid_files', `Choose between 1 and ${maxFiles} files.`);
    let total = 0;
    const list = [];
    for (const f of files) {
      if (!validName(f?.name) || !Number.isSafeInteger(f?.size) || f.size < 0 || f.size > maxFile || !/^[a-f\d]{64}$/i.test(f?.sha256 || '')) return error(res, 400, 'invalid_file_metadata', 'File metadata is invalid or exceeds the configured limit.');
      total += f.size;
      list.push({ name: f.name, size: f.size, mimeType: typeof f.mimeType === 'string' ? f.mimeType.slice(0, 160) : 'application/octet-stream', sha256: f.sha256.toLowerCase(), uploaded: false, verified: false, storedName: null });
    }
    if (total > maxFile) return error(res, 413, 'transfer_too_large', 'The transfer exceeds the configured size limit.');
    const t = { id: crypto.randomUUID(), senderId: req.device.id, receiverId, status: 'pending', files: list, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    state.transfers[t.id] = t; await save();
    res.status(201).json({ success: true, transfer: view(t) });
  } catch (e) { next(e); }
});
app.get('/api/transfers', authenticate, async (req, res, next) => {
  try {
    await save();
    const transfers = Object.values(state.transfers).filter((t) => t.senderId === req.device.id || t.receiverId === req.device.id).sort((a, b) => b.createdAt.localeCompare(a.createdAt)).map(view);
    res.json({ success: true, transfers });
  } catch (e) { next(e); }
});
for (const [action, status] of [['accept', 'accepted'], ['reject', 'rejected']]) app.post(`/api/transfers/:transferId/${action}`, authenticate, async (req, res, next) => {
  try {
    const t = getTransfer(req, res, 'receiver'); if (!t) return;
    if (t.status !== 'pending') return error(res, 409, 'invalid_state', 'This transfer is no longer awaiting a response.');
    t.status = status; t.updatedAt = new Date().toISOString(); await save();
    res.json({ success: true, transfer: view(t) });
  } catch (e) { next(e); }
});
app.post('/api/transfers/:transferId/cancel', authenticate, async (req, res, next) => {
  try {
    const t = getTransfer(req, res, 'member'); if (!t) return;
    if (['completed', 'rejected', 'cancelled'].includes(t.status)) return error(res, 409, 'invalid_state', 'This transfer is already finished.');
    t.status = 'cancelled'; t.updatedAt = new Date().toISOString();
    for (const f of t.files) if (f.storedName) await fsp.rm(path.join(transferDir, f.storedName), { force: true });
    await save(); res.json({ success: true, transfer: view(t) });
  } catch (e) { next(e); }
});
app.post('/api/transfers/:transferId/complete', authenticate, async (req, res, next) => {
  try {
    const t = getTransfer(req, res, 'receiver'); if (!t) return;
    if (t.status !== 'ready' || !t.files.every((f) => f.uploaded && f.verified)) return error(res, 409, 'not_ready', 'All files must be uploaded and verified before completion.');
    t.status = 'completed'; t.updatedAt = new Date().toISOString(); await save();
    res.json({ success: true, transfer: view(t) });
  } catch (e) { next(e); }
});

const storage = multer.diskStorage({ destination: (_req, _file, cb) => cb(null, transferDir), filename: (req, _file, cb) => cb(null, `${req.params.transferId}-${req.params.fileIndex}-${crypto.randomBytes(8).toString('hex')}.part`) });
const upload = multer({ storage, limits: { fileSize: maxFile, files: 1 } });
app.post('/api/transfers/:transferId/files/:fileIndex', authenticate, (req, res, next) => {
  const t = getTransfer(req, res, 'sender'); if (!t) return;
  const i = Number(req.params.fileIndex), file = t.files[i];
  if (t.status !== 'accepted' || !Number.isInteger(i) || !file) return error(res, 409, 'invalid_state', 'Transfer is not ready for this file.');
  if (file.uploaded) return error(res, 409, 'duplicate_file', 'This file was already uploaded.');
  t.status = 'uploading';
  upload.single('file')(req, res, async (err) => {
    try {
      if (err) { t.status = 'accepted'; await save(); return next(err); }
      if (!req.file) { t.status = 'accepted'; await save(); return error(res, 400, 'missing_file', 'No file was provided.'); }
      const hash = crypto.createHash('sha256');
      for await (const chunk of fs.createReadStream(req.file.path)) hash.update(chunk);
      const digest = hash.digest('hex');
      if (req.file.size !== file.size || !equalSecret(digest, file.sha256)) {
        await fsp.rm(req.file.path, { force: true });
        t.status = 'accepted'; await save();
        return error(res, 422, 'integrity_mismatch', 'Uploaded bytes did not match the expected size and SHA-256.');
      }
      const storedName = `${t.id}-${i}-${crypto.randomBytes(8).toString('hex')}.bin`;
      await fsp.rename(req.file.path, path.join(transferDir, storedName));
      file.storedName = storedName; file.uploaded = true; file.verified = true;
      t.status = t.files.every((x) => x.uploaded) ? 'ready' : 'accepted'; t.updatedAt = new Date().toISOString();
      await save(); res.json({ success: true, verified: true, file: { name: file.name, size: file.size, sha256: digest } });
    } catch (e) { next(e); }
  });
});
app.get('/api/transfers/:transferId/files/:fileIndex', authenticate, (req, res, next) => {
  const t = getTransfer(req, res, 'receiver'); if (!t) return;
  const f = t.files[Number(req.params.fileIndex)];
  if (!f?.uploaded || !f.verified || !f.storedName) return error(res, 404, 'not_found', 'Verified file is not available yet.');
  res.setHeader('Content-Type', f.mimeType || 'application/octet-stream'); res.setHeader('Content-Length', String(f.size));
  res.setHeader('Content-Disposition', `attachment; filename="${f.name.replace(/[\r\n"\\]/g, '_')}"`);
  const stream = fs.createReadStream(path.join(transferDir, f.storedName)); stream.on('error', next); stream.pipe(res);
});

// Legacy two-user image demo routes remain available during migration.
const pending = new Map();
const legacyUpload = multer({ storage: multer.diskStorage({ destination: (_r, _f, cb) => cb(null, path.join(root, 'uploads')), filename: (_r, f, cb) => cb(null, `image-${Date.now()}-${crypto.randomBytes(5).toString('hex')}${path.extname(f.originalname).slice(0, 12)}`) }), limits: { fileSize: maxFile, files: 1 } });
app.post('/upload', legacyUpload.single('image'), (req, res) => {
  if (!req.file || typeof req.body.userId !== 'string') return error(res, 400, 'missing_file', 'An image and userId are required.');
  pending.set(req.body.userId, `/uploads/${req.file.filename}`); res.json({ success: true, message: 'Image uploaded successfully', imagePath: `/uploads/${req.file.filename}` });
});
app.get('/drop/:receiverId', (req, res) => {
  const sender = ({ id1: 'id2', id2: 'id1' })[req.params.receiverId], imagePath = sender && pending.get(sender);
  if (!imagePath) return res.json({ success: false, message: 'No image available from your friend' });
  pending.delete(sender); return res.json({ success: true, imagePath, message: 'Image received' });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  if (err instanceof multer.MulterError) return error(res, err.code === 'LIMIT_FILE_SIZE' ? 413 : 400, err.code.toLowerCase(), err.message);
  return error(res, 500, 'internal_error', 'The server could not complete the request.');
});
app.listen(port, () => console.log(`DropIt API listening on port ${port}`));
