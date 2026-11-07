import type { Request, Response } from "express";
import { createHash, randomBytes } from "node:crypto";
import { getDb } from "./db.js";

/* جلسات مخزّنة في PostgreSQL: الكوكي يحمل رمزاً عشوائياً، والقاعدة تحفظ بصمته (SHA-256) فقط. */

export type SessionUser = { id: number; email: string; role: "admin" | "team"; isAdmin: boolean };

const COOKIE = "ent_sid";
const TTL_MS = 7 * 24 * 3600_000; // أسبوع، ويتجدد مع الاستخدام
const RENEW_AFTER_MS = 3600_000;

const secure = process.env.NODE_ENV === "production" || process.env.RENDER === "true";
const attrs = `Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export function readCookie(req: Request, name: string): string {
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) {
      try { return decodeURIComponent(part.slice(i + 1).trim()); } catch { return ""; }
    }
  }
  return "";
}

const setCookie = (res: Response, token: string, maxAgeS: number) =>
  res.setHeader("Set-Cookie", `${COOKIE}=${encodeURIComponent(token)}; ${attrs}; Max-Age=${maxAgeS}`);

export async function createSession(res: Response, userId: number) {
  const db = await getDb();
  const token = randomBytes(32).toString("base64url");
  await db.query("INSERT INTO entilaaqa.sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + $3::int * interval '1 second')", [sha(token), userId, TTL_MS / 1000]);
  await db.query("UPDATE entilaaqa.users SET last_login_at = now() WHERE id = $1", [userId]);
  setCookie(res, token, TTL_MS / 1000);
}

export async function destroySession(req: Request, res: Response) {
  const token = readCookie(req, COOKIE);
  if (token) {
    try { await (await getDb()).query("DELETE FROM entilaaqa.sessions WHERE token_hash = $1", [sha(token)]); } catch { /* نمسح الكوكي على أي حال */ }
  }
  setCookie(res, "", 0);
}

/** المستخدم الحالي من الكوكي، أو null. يجدّد الجلسة تلقائياً (sliding). */
export async function currentUser(req: Request, res: Response): Promise<SessionUser | null> {
  const token = readCookie(req, COOKIE);
  if (!token) return null;
  const db = await getDb();
  const { rows } = await db.query(
    `SELECT u.id, u.email, u.role, s.renewed_at
       FROM entilaaqa.sessions s JOIN entilaaqa.users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > now() AND u.active`,
    [sha(token)],
  );
  const r = rows[0];
  if (!r) return null;
  if (Date.now() - new Date(r.renewed_at).getTime() > RENEW_AFTER_MS) {
    await db.query("UPDATE entilaaqa.sessions SET expires_at = now() + $2::int * interval '1 second', renewed_at = now() WHERE token_hash = $1", [sha(token), TTL_MS / 1000]);
    setCookie(res, token, TTL_MS / 1000);
  }
  return { id: r.id, email: r.email, role: r.role, isAdmin: r.role === "admin" };
}

/* ---------- تحديد المحاولات (في الذاكرة، يكفي لخدمة واحدة) ---------- */
type Bucket = { n: number; until: number };
export function limiter(max: number, windowMs: number) {
  const m = new Map<string, Bucket>();
  setInterval(() => { const t = Date.now(); for (const [k, b] of m) if (b.until < t) m.delete(k); }, 60_000).unref();
  return {
    blocked: (key: string) => { const b = m.get(key); return !!b && b.until > Date.now() && b.n >= max; },
    hit: (key: string) => {
      const t = Date.now(), b = m.get(key);
      if (!b || b.until < t) m.set(key, { n: 1, until: t + windowMs });
      else b.n++;
    },
    reset: (key: string) => void m.delete(key),
  };
}

export const clientIp = (req: Request) => String(req.headers["cf-connecting-ip"] || req.ip || "unknown");
