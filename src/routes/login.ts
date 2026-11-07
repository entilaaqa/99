import type { Request, Response } from "express";
import { clientIp, createSession, limiter } from "../auth.js";
import { getDb } from "../db.js";
import { DUMMY_HASH, verifyPassword } from "../password.js";

const byIp = limiter(30, 15 * 60_000);
const byEmail = limiter(8, 15 * 60_000);

/* POST /api/login {email, password} → يتحقق من PostgreSQL ويضع كوكي جلسة آمن (HttpOnly). */
export default async function login(req: Request, res: Response) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "method_not_allowed" });
  }
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase().slice(0, 254) : "";
  const password = typeof req.body?.password === "string" ? req.body.password.slice(0, 200) : "";
  if (!email || !password) return res.status(400).json({ ok: false, error: "invalid_input" });

  const ip = clientIp(req);
  if (byIp.blocked(ip) || byEmail.blocked(email)) return res.status(429).json({ ok: false, error: "too_many_attempts" });

  let db;
  try { db = await getDb(); } catch (e) {
    console.error("login: database unavailable", (e as Error).message);
    return res.status(503).json({ ok: false, error: "auth_not_configured" });
  }

  const { rows } = await db.query("SELECT id, password_hash, active FROM entilaaqa.users WHERE email = $1", [email]);
  const u = rows[0];
  const ok = await verifyPassword(password, u?.password_hash ?? DUMMY_HASH);
  if (!u || !u.active || !ok) {
    byIp.hit(ip);
    byEmail.hit(email);
    return res.status(401).json({ ok: false, error: "invalid_credentials" });
  }
  byEmail.reset(email);
  await createSession(res, u.id);
  return res.status(200).json({ ok: true, redirect: "/dashboard.html" });
}
