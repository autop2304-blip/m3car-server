import 'dotenv/config';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  computeQuoteHandler,
  reverseGeocodeServer,
  RoutePricingError,
  searchPlacesServer,
  validateOrderPricingHandler,
} from './src/server/routePricingEngine.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const ADMIN_SESSION_COOKIE = 'm3car_admin_session';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

// SHA-256 digest of the initial admin access code so no plaintext code is embedded in source
const DEFAULT_ADMIN_CODE_SHA256 =
  'a908081aae8d37b4a67184aae945148aa6954b56e068067de718e6692db02d22';

let runtimeOverrideSha256: string | null = null;

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function normalizeEnvSecret(raw: string | undefined): string {
  if (!raw) return '';
  let val = raw.trim();
  if (
    (val.startsWith('"') && val.endsWith('"')) ||
    (val.startsWith("'") && val.endsWith("'"))
  ) {
    val = val.slice(1, -1).trim();
  }
  return val;
}

const PLACEHOLDER_ENV_VALUES = new Set([
  'ADMIN_ACCESS_CODE',
  'MY_ADMIN_ACCESS_CODE',
  'YOUR_ADMIN_ACCESS_CODE',
  'ADMIN_SESSION_SECRET',
  'MY_ADMIN_SESSION_SECRET',
  'CHANGE_ME',
]);

function getExpectedAdminHashHex(): string {
  if (runtimeOverrideSha256) {
    return runtimeOverrideSha256;
  }
  const envCode = normalizeEnvSecret(process.env.ADMIN_ACCESS_CODE);
  if (envCode.length > 0 && !PLACEHOLDER_ENV_VALUES.has(envCode.toUpperCase())) {
    return sha256Hex(envCode);
  }
  return DEFAULT_ADMIN_CODE_SHA256;
}

function getSessionSecret(): string {
  const envSecret = normalizeEnvSecret(process.env.ADMIN_SESSION_SECRET);
  if (envSecret.length >= 16 && !PLACEHOLDER_ENV_VALUES.has(envSecret.toUpperCase())) {
    return envSecret;
  }
  return sha256Hex(`m3car-session-key:${getExpectedAdminHashHex()}`);
}

function safeEqualHex(aHex: string, bHex: string): boolean {
  const aBuf = Buffer.from(aHex, 'hex');
  const bBuf = Buffer.from(bHex, 'hex');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

interface SessionPayload {
  role: 'admin';
  name: string;
  jti: string;
  iat: number;
  exp: number;
}

const revokedTokenIds = new Set<string>();

function signAdminSessionToken(): { token: string; payload: SessionPayload } {
  const now = Date.now();
  const payload: SessionPayload = {
    role: 'admin',
    name: 'Admin Pusat M3CAR',
    jti: crypto.randomUUID(),
    iat: now,
    exp: now + SESSION_TTL_MS,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = crypto
    .createHmac('sha256', getSessionSecret())
    .update(encodedPayload)
    .digest('base64url');
  return { token: `${encodedPayload}.${sig}`, payload };
}

function verifyAdminSessionToken(token: string | undefined): SessionPayload | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encodedPayload, providedSig] = parts;
  if (!encodedPayload || !providedSig) return null;

  const expectedSig = crypto
    .createHmac('sha256', getSessionSecret())
    .update(encodedPayload)
    .digest('base64url');

  const providedBuf = Buffer.from(providedSig, 'utf8');
  const expectedBuf = Buffer.from(expectedSig, 'utf8');
  if (providedBuf.length !== expectedBuf.length) return null;
  if (!crypto.timingSafeEqual(providedBuf, expectedBuf)) return null;

  try {
    const decoded = JSON.parse(
      Buffer.from(encodedPayload, 'base64url').toString('utf8')
    ) as SessionPayload;
    if (decoded.role !== 'admin') return null;
    if (typeof decoded.exp !== 'number' || decoded.exp <= Date.now()) return null;
    if (!decoded.jti || revokedTokenIds.has(decoded.jti)) return null;
    return decoded;
  } catch {
    return null;
  }
}

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx > -1) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      if (k) out[k] = decodeURIComponent(v);
    }
  }
  return out;
}

function extractToken(req: Request): string | undefined {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    const bearer = authHeader.slice(7).trim();
    if (bearer) return bearer;
  }
  const cookies = parseCookies(req.headers.cookie);
  return cookies[ADMIN_SESSION_COOKIE];
}

function setSessionCookie(req: Request, res: Response, token: string): void {
  const isHttps =
    req.secure ||
    req.headers['x-forwarded-proto'] === 'https' ||
    process.env.NODE_ENV === 'production';

  const attributes = [
    `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
    isHttps ? 'SameSite=None' : 'SameSite=Lax',
  ];
  if (isHttps) {
    attributes.push('Secure');
  }
  res.setHeader('Set-Cookie', attributes.join('; '));
}

function clearSessionCookie(req: Request, res: Response): void {
  const isHttps =
    req.secure ||
    req.headers['x-forwarded-proto'] === 'https' ||
    process.env.NODE_ENV === 'production';

  const attributes = [
    `${ADMIN_SESSION_COOKIE}=`,
    'Path=/',
    'HttpOnly',
    'Max-Age=0',
    isHttps ? 'SameSite=None' : 'SameSite=Lax',
  ];
  if (isHttps) {
    attributes.push('Secure');
  }
  res.setHeader('Set-Cookie', attributes.join('; '));
}

interface AuthedRequest extends Request {
  adminSession?: SessionPayload;
}

function requireAdminAuth(req: AuthedRequest, res: Response, next: NextFunction): void {
  const token = extractToken(req);
  const payload = verifyAdminSessionToken(token);
  if (!payload) {
    res.status(401).json({
      ok: false,
      authenticated: false,
      message: 'Sesi Admin tidak valid atau sudah berakhir.',
    });
    return;
  }
  req.adminSession = payload;
  next();
}

async function startServer(): Promise<void> {
  const app = express();
  const httpServer = http.createServer(app);
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '2mb' }));

  // Server-side Admin Login (verifies secret server code, never exposed in frontend)
  app.post('/api/admin/login', (req: Request, res: Response) => {
    const rawCode = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
    if (!rawCode) {
      res.status(400).json({ ok: false, message: 'Kode Admin wajib diisi.' });
      return;
    }

    const inputHash = sha256Hex(rawCode);
    const expectedHash = getExpectedAdminHashHex();
    if (!safeEqualHex(inputHash, expectedHash)) {
      res.status(401).json({ ok: false, message: 'Kode Salah' });
      return;
    }

    const { token, payload } = signAdminSessionToken();
    setSessionCookie(req, res, token);
    res.json({
      ok: true,
      authenticated: true,
      token,
      expiresAt: payload.exp,
      user: {
        id: 'admin-root',
        name: payload.name,
        role: 'admin',
      },
    });
  });

  // Server-side Session Verification
  app.get('/api/admin/session', requireAdminAuth, (req: AuthedRequest, res: Response) => {
    res.json({
      ok: true,
      authenticated: true,
      expiresAt: req.adminSession?.exp,
      user: {
        id: 'admin-root',
        name: req.adminSession?.name || 'Admin Pusat M3CAR',
        role: 'admin',
      },
    });
  });

  // Server-side Protected Action Guard Check
  app.post('/api/admin/verify', requireAdminAuth, (_req: AuthedRequest, res: Response) => {
    res.json({ ok: true, verified: true });
  });

  // Server-side Admin Access Code Rotation (protected by active Admin session)
  app.post('/api/admin/change-code', requireAdminAuth, (req: AuthedRequest, res: Response) => {
    const currentCode =
      typeof req.body?.currentCode === 'string' ? req.body.currentCode.trim() : '';
    const newCode = typeof req.body?.newCode === 'string' ? req.body.newCode.trim() : '';

    if (!currentCode || !newCode || newCode.length < 6) {
      res.status(400).json({
        ok: false,
        message: 'Kode saat ini dan kode baru minimal 6 karakter wajib diisi.',
      });
      return;
    }

    if (!safeEqualHex(sha256Hex(currentCode), getExpectedAdminHashHex())) {
      res.status(401).json({ ok: false, message: 'Kode Admin saat ini salah.' });
      return;
    }

    runtimeOverrideSha256 = sha256Hex(newCode);
    const { token, payload } = signAdminSessionToken();
    setSessionCookie(req, res, token);
    res.json({
      ok: true,
      token,
      expiresAt: payload.exp,
      message: 'Kode Akses Admin server berhasil diperbarui untuk sesi berjalan.',
    });
  });

  // Server-side Logout
  app.post('/api/admin/logout', (req: Request, res: Response) => {
    const token = extractToken(req);
    const payload = verifyAdminSessionToken(token);
    if (payload?.jti) {
      revokedTokenIds.add(payload.jti);
    }
    clearSessionCookie(req, res);
    res.json({ ok: true });
  });

  // =========================================================================
  // DRIVER ACCOUNT SECURITY API (Scrypt Server Hashing & Verified Recovery)
  // =========================================================================
  const DRIVER_SESSION_COOKIE = 'm3car_driver_session';

  function hashPasswordScrypt(secret: string): string {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = crypto.scryptSync(secret, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
    return `scrypt$${salt}$${derived}`;
  }

  function verifyPasswordScrypt(secret: string, storedHash: string): boolean {
    if (!secret || !storedHash || typeof storedHash !== 'string') return false;
    const parts = storedHash.split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const [, salt, expectedHex] = parts;
    if (!salt || !expectedHex) return false;
    try {
      const derivedHex = crypto
        .scryptSync(secret, salt, 64, { N: 16384, r: 8, p: 1 })
        .toString('hex');
      return safeEqualHex(derivedHex, expectedHex);
    } catch {
      return false;
    }
  }

  function normalizePhoneServer(raw: unknown): string {
    if (typeof raw !== 'string') return '';
    let cleaned = raw.replace(/\D/g, '');
    if (cleaned.startsWith('62')) {
      cleaned = '0' + cleaned.slice(2);
    } else if (cleaned.startsWith('8')) {
      cleaned = '0' + cleaned;
    }
    return cleaned;
  }

  function normalizePlateServer(raw: unknown): string {
    if (typeof raw !== 'string') return '';
    return raw.toUpperCase().replace(/[^A-Z0-9]/g, '');
  }

  function normalizeNameServer(raw: unknown): string {
    if (typeof raw !== 'string') return '';
    return raw.trim().toLowerCase().replace(/\s+/g, ' ');
  }

  function validatePasswordPolicy(password: unknown, confirmPassword: unknown): string | null {
    if (typeof password !== 'string' || password.length < 6) {
      return 'Kata sandi pribadi minimal 6 karakter.';
    }
    if (password.length > 128 || password.includes('\0')) {
      return 'Format kata sandi tidak valid.';
    }
    if (!password.trim()) {
      return 'Kata sandi tidak boleh hanya berisi spasi.';
    }
    if (password !== confirmPassword) {
      return 'Konfirmasi kata sandi tidak cocok. Ulangi kata sandi yang sama.';
    }
    return null;
  }

  interface DriverSessionPayload {
    role: 'driver';
    driverId: string;
    phone: string;
    name: string;
    jti: string;
    iat: number;
    exp: number;
  }

  function signDriverSessionToken(driverId: string, phone: string, name: string) {
    const now = Date.now();
    const payload: DriverSessionPayload = {
      role: 'driver',
      driverId,
      phone,
      name,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + SESSION_TTL_MS,
    };
    const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig = crypto
      .createHmac('sha256', getSessionSecret())
      .update(encodedPayload)
      .digest('base64url');
    return { token: `${encodedPayload}.${sig}`, payload };
  }

  function verifyDriverSessionToken(token: string | undefined): DriverSessionPayload | null {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [encodedPayload, providedSig] = parts;
    if (!encodedPayload || !providedSig) return null;

    const expectedSig = crypto
      .createHmac('sha256', getSessionSecret())
      .update(encodedPayload)
      .digest('base64url');

    const providedBuf = Buffer.from(providedSig, 'utf8');
    const expectedBuf = Buffer.from(expectedSig, 'utf8');
    if (providedBuf.length !== expectedBuf.length) return null;
    if (!crypto.timingSafeEqual(providedBuf, expectedBuf)) return null;

    try {
      const decoded = JSON.parse(
        Buffer.from(encodedPayload, 'base64url').toString('utf8')
      ) as DriverSessionPayload;
      if (decoded.role !== 'driver') return null;
      if (typeof decoded.exp !== 'number' || decoded.exp <= Date.now()) return null;
      if (!decoded.jti || revokedTokenIds.has(decoded.jti)) return null;
      return decoded;
    } catch {
      return null;
    }
  }

  function setDriverCookie(req: Request, res: Response, token: string, maxAgeSeconds: number) {
    const isHttps =
      req.secure ||
      req.headers['x-forwarded-proto'] === 'https' ||
      process.env.NODE_ENV === 'production';
    const attrs = [
      `${DRIVER_SESSION_COOKIE}=${encodeURIComponent(token)}`,
      'Path=/',
      'HttpOnly',
      `Max-Age=${maxAgeSeconds}`,
      isHttps ? 'SameSite=None' : 'SameSite=Lax',
    ];
    if (isHttps) attrs.push('Secure');
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  app.post('/api/driver/hash-password', (req: Request, res: Response) => {
    const errMsg = validatePasswordPolicy(req.body?.password, req.body?.confirmPassword);
    if (errMsg) {
      res.status(400).json({ ok: false, message: errMsg });
      return;
    }
    const passwordHash = hashPasswordScrypt(String(req.body.password));
    res.json({
      ok: true,
      passwordHash,
      hasPassword: true,
      passwordUpdatedAt: new Date().toISOString(),
    });
  });

  app.post('/api/driver/verify-password', (req: Request, res: Response) => {
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const passwordHash = typeof req.body?.passwordHash === 'string' ? req.body.passwordHash : '';
    const driverId = typeof req.body?.driverId === 'string' ? req.body.driverId : '';
    const phone = normalizePhoneServer(req.body?.phone);
    const name = typeof req.body?.name === 'string' ? req.body.name : 'Driver M3CAR';
    const status = String(req.body?.status || '').toUpperCase().trim();

    if (!password || !passwordHash) {
      res.status(400).json({ ok: false, message: 'Nomor HP dan kata sandi wajib diisi.' });
      return;
    }

    if (!verifyPasswordScrypt(password, passwordHash)) {
      res.status(401).json({
        ok: false,
        verified: false,
        message: 'Kata sandi salah. Periksa kembali kata sandi Anda atau gunakan Lupa Kata Sandi.',
      });
      return;
    }

    if (status === 'MENUNGGU' || status === 'WAITING_APPROVAL' || status === 'PENDING') {
      res.status(403).json({
        ok: false,
        verified: true,
        pendingApproval: true,
        message:
          'Akun Anda masih berstatus MENUNGGU PERSETUJUAN ADMIN. Login dibuka setelah Admin menyetujui pendaftaran Anda.',
      });
      return;
    }

    if (status === 'DIBLOKIR' || status === 'BLOCKED') {
      res.status(403).json({
        ok: false,
        verified: true,
        blocked: true,
        message: 'Akun Driver Anda sedang DIBLOKIR oleh Admin. Hubungi Admin Pusat M3CAR.',
      });
      return;
    }

    const { token, payload } = signDriverSessionToken(driverId, phone, name);
    setDriverCookie(req, res, token, Math.floor(SESSION_TTL_MS / 1000));
    res.json({
      ok: true,
      verified: true,
      rejected: status === 'DITOLAK' || status === 'REJECTED',
      token,
      expiresAt: payload.exp,
      user: {
        id: driverId,
        phone,
        name,
        role: 'driver',
      },
    });
  });

  app.post('/api/driver/first-password', (req: Request, res: Response) => {
    const hasExistingPassword = Boolean(req.body?.hasExistingPassword);
    if (hasExistingPassword) {
      res.status(409).json({
        ok: false,
        message: 'Akun driver ini sudah memiliki kata sandi. Silakan masuk atau gunakan Lupa Kata Sandi.',
      });
      return;
    }

    const phone = normalizePhoneServer(req.body?.phone);
    const storedPhone = normalizePhoneServer(req.body?.storedPhone);
    const plate = normalizePlateServer(req.body?.plateNumber);
    const storedPlate = normalizePlateServer(req.body?.storedPlate);

    if (!phone || !storedPhone || phone !== storedPhone) {
      res.status(400).json({ ok: false, message: 'Nomor HP tidak sesuai dengan data driver.' });
      return;
    }

    if (storedPlate) {
      if (!plate || plate !== storedPlate) {
        res.status(401).json({
          ok: false,
          message: 'Nomor Polisi (Plat Kendaraan) tidak cocok dengan data driver lama.',
        });
        return;
      }
    } else {
      const fullName = normalizeNameServer(req.body?.fullName);
      const storedName = normalizeNameServer(req.body?.storedName);
      if (!fullName || !storedName || fullName !== storedName) {
        res.status(401).json({
          ok: false,
          message: 'Nama Lengkap tidak cocok dengan data driver lama.',
        });
        return;
      }
    }

    const errMsg = validatePasswordPolicy(req.body?.password, req.body?.confirmPassword);
    if (errMsg) {
      res.status(400).json({ ok: false, message: errMsg });
      return;
    }

    const passwordHash = hashPasswordScrypt(String(req.body.password));
    res.json({
      ok: true,
      passwordHash,
      hasPassword: true,
      passwordUpdatedAt: new Date().toISOString(),
    });
  });

  app.post('/api/driver/recover-password', (req: Request, res: Response) => {
    const phone = normalizePhoneServer(req.body?.phone);
    const storedPhone = normalizePhoneServer(req.body?.storedPhone);
    if (!phone || !storedPhone || phone !== storedPhone) {
      res.status(400).json({ ok: false, message: 'Nomor HP driver tidak ditemukan.' });
      return;
    }

    const recoveryCode =
      typeof req.body?.recoveryCode === 'string' ? req.body.recoveryCode.trim() : '';
    const storedRecoveryCodeHash =
      typeof req.body?.storedRecoveryCodeHash === 'string' ? req.body.storedRecoveryCodeHash : '';
    const storedRecoveryExpiresAt =
      typeof req.body?.storedRecoveryExpiresAt === 'string' ? req.body.storedRecoveryExpiresAt : '';

    let verifiedIdentity = false;

    if (recoveryCode && storedRecoveryCodeHash) {
      const notExpired =
        !storedRecoveryExpiresAt || Date.parse(storedRecoveryExpiresAt) > Date.now();
      if (notExpired && verifyPasswordScrypt(recoveryCode, storedRecoveryCodeHash)) {
        verifiedIdentity = true;
      } else {
        res.status(401).json({
          ok: false,
          message: 'Kode Pemulihan dari Admin tidak valid atau sudah kedaluwarsa.',
        });
        return;
      }
    } else {
      const plate = normalizePlateServer(req.body?.plateNumber);
      const storedPlate = normalizePlateServer(req.body?.storedPlate);
      const fullName = normalizeNameServer(req.body?.fullName);
      const storedName = normalizeNameServer(req.body?.storedName);

      if (plate && storedPlate && plate === storedPlate && fullName && storedName && fullName === storedName) {
        verifiedIdentity = true;
      }
    }

    if (!verifiedIdentity) {
      res.status(401).json({
        ok: false,
        message:
          'Verifikasi pemulihan gagal. Pastikan Nomor Polisi dan Nama Lengkap sesuai pendaftaran, atau masukkan Kode Pemulihan dari Admin.',
      });
      return;
    }

    const errMsg = validatePasswordPolicy(req.body?.newPassword, req.body?.confirmPassword);
    if (errMsg) {
      res.status(400).json({ ok: false, message: errMsg });
      return;
    }

    const passwordHash = hashPasswordScrypt(String(req.body.newPassword));
    res.json({
      ok: true,
      passwordHash,
      hasPassword: true,
      clearRecovery: true,
      passwordUpdatedAt: new Date().toISOString(),
    });
  });

  app.post('/api/driver/generate-recovery-code', requireAdminAuth, (_req: AuthedRequest, res: Response) => {
    const code = String(crypto.randomInt(100000, 999999));
    const recoveryCodeHash = hashPasswordScrypt(code);
    const recoveryCodeExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    res.json({
      ok: true,
      recoveryCode: code,
      recoveryCodeHash,
      recoveryCodeExpiresAt,
    });
  });

  app.get('/api/driver/session', (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    const bearer =
      authHeader && authHeader.toLowerCase().startsWith('bearer ')
        ? authHeader.slice(7).trim()
        : undefined;
    const cookies = parseCookies(req.headers.cookie);
    const payload = verifyDriverSessionToken(bearer || cookies[DRIVER_SESSION_COOKIE]);
    if (!payload) {
      res.status(401).json({ ok: false, authenticated: false });
      return;
    }
    res.json({
      ok: true,
      authenticated: true,
      user: {
        id: payload.driverId,
        phone: payload.phone,
        name: payload.name,
        role: 'driver',
      },
    });
  });

  app.post('/api/driver/logout', (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    const bearer =
      authHeader && authHeader.toLowerCase().startsWith('bearer ')
        ? authHeader.slice(7).trim()
        : undefined;
    const cookies = parseCookies(req.headers.cookie);
    const payload = verifyDriverSessionToken(bearer || cookies[DRIVER_SESSION_COOKIE]);
    if (payload?.jti) revokedTokenIds.add(payload.jti);
    setDriverCookie(req, res, '', 0);
    res.json({ ok: true });
  });

  // ============================================================================
  // AUTOMATIC GPS ROAD-DISTANCE PRICING & GEOCODING API (Server-Side Protected)
  // ============================================================================
  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({
      ok: true,
      hasGoogleMapsKey: Boolean(process.env.GOOGLE_MAPS_API_KEY?.trim()),
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/routes/search', async (req: Request, res: Response) => {
    try {
      const q = typeof req.query.q === 'string' ? req.query.q : '';
      const results = await searchPlacesServer(q);
      res.json({ results });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Gagal mencari lokasi', results: [] });
    }
  });

  app.get('/api/routes/reverse-geocode', async (req: Request, res: Response) => {
    try {
      const lat = Number(req.query.lat);
      const lng = Number(req.query.lng);
      const result = await reverseGeocodeServer(lat, lng);
      res.json({ result });
    } catch (err: any) {
      res.status(500).json({ error: err?.message || 'Gagal membaca alamat GPS', result: null });
    }
  });

  app.post('/api/routes/quote', async (req: Request, res: Response) => {
    try {
      const quote = await computeQuoteHandler(req.body);
      res.json(quote);
    } catch (err: any) {
      if (err instanceof RoutePricingError) {
        res.status(err.status).json({ error: err.message, code: err.code });
        return;
      }
      res.status(500).json({
        error: err?.message || 'Gagal menghitung tarif rute otomatis',
        code: 'INTERNAL_ERROR',
      });
    }
  });

  app.post('/api/orders/validate-pricing', async (req: Request, res: Response) => {
    try {
      const validated = await validateOrderPricingHandler(req.body);
      res.json(validated);
    } catch (err: any) {
      if (err instanceof RoutePricingError) {
        res.status(err.status).json({ error: err.message, code: err.code });
        return;
      }
      res.status(500).json({
        error: err?.message || 'Gagal memvalidasi tarif pesanan di server',
        code: 'INTERNAL_ERROR',
      });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
        ws: { server: httpServer },
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`M3CAR Admin Panel server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start M3CAR server:', err);
  process.exit(1);
});
