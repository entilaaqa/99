import type { Request, Response } from "express";
import { currentUser } from "../auth.js";
import { getDb } from "../db.js";
import { hashPassword } from "../password.js";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const ROLES = ["admin", "team"];

/* إدارة المستخدمين (للمدير فقط): GET قائمة · POST إنشاء · PATCH تعديل (كلمة مرور/دور/تفعيل) · DELETE حذف */
export default async function users(req: Request, res: Response) {
  res.setHeader("Cache-Control", "no-store");
  const me = await currentUser(req, res);
  if (!me) return res.status(401).json({ ok: false });
  if (!me.isAdmin) return res.status(403).json({ ok: false, error: "forbidden" });
  const db = await getDb();
  const bad = (error = "invalid_input") => res.status(400).json({ ok: false, error });
  const b = req.body ?? {};

  if (req.method === "GET") {
    const { rows } = await db.query("SELECT id, email, role, active, created_at, last_login_at FROM entilaaqa.users ORDER BY id");
    return res.json({ ok: true, users: rows, me: me.id });
  }

  if (req.method === "POST") {
    const email = typeof b.email === "string" ? b.email.trim().toLowerCase().slice(0, 254) : "";
    const password = typeof b.password === "string" ? b.password : "";
    const role = b.role ?? "team";
    if (!EMAIL.test(email) || password.length < 10 || password.length > 200 || !ROLES.includes(role)) return bad();
    try {
      await db.query("INSERT INTO entilaaqa.users (email, password_hash, role) VALUES ($1, $2, $3)", [email, await hashPassword(password), role]);
    } catch (e: any) {
      if (e?.code === "23505") return bad("exists");
      throw e;
    }
    return res.status(201).json({ ok: true });
  }

  const id = Number(b.id ?? req.query.id);
  if (!Number.isInteger(id)) return bad();
  const target = (await db.query("SELECT id, role, active FROM entilaaqa.users WHERE id = $1", [id])).rows[0];
  if (!target) return res.status(404).json({ ok: false, error: "not_found" });

  // لا نسمح بإزالة آخر مدير فعّال، ولا بإيقاف/حذف المدير لحسابه.
  const lastAdminGuard = async () => {
    const n = (await db.query("SELECT count(*)::int AS n FROM entilaaqa.users WHERE role = 'admin' AND active AND id <> $1", [id])).rows[0].n;
    return n === 0;
  };

  if (req.method === "DELETE") {
    if (id === me.id) return bad("self");
    if (target.role === "admin" && target.active && (await lastAdminGuard())) return bad("last_admin");
    await db.query("DELETE FROM entilaaqa.users WHERE id = $1", [id]);
    return res.json({ ok: true });
  }

  if (req.method === "PATCH") {
    const sets: string[] = [];
    const vals: unknown[] = [];
    if (b.password !== undefined) {
      if (typeof b.password !== "string" || b.password.length < 10 || b.password.length > 200) return bad();
      vals.push(await hashPassword(b.password)); sets.push(`password_hash = $${vals.length}`);
    }
    if (b.role !== undefined) {
      if (!ROLES.includes(b.role)) return bad();
      if (b.role !== "admin" && target.role === "admin" && (id === me.id || (await lastAdminGuard()))) return bad(id === me.id ? "self" : "last_admin");
      vals.push(b.role); sets.push(`role = $${vals.length}`);
    }
    if (b.active !== undefined) {
      if (typeof b.active !== "boolean") return bad();
      if (!b.active && (id === me.id || (target.role === "admin" && (await lastAdminGuard())))) return bad(id === me.id ? "self" : "last_admin");
      vals.push(b.active); sets.push(`active = $${vals.length}`);
    }
    if (!sets.length) return bad();
    vals.push(id);
    await db.query(`UPDATE entilaaqa.users SET ${sets.join(", ")} WHERE id = $${vals.length}`, vals);
    // تغيير كلمة المرور أو الإيقاف يُنهي جلسات ذلك المستخدم (ما عدا جلسة المدير الحالية لحسابه).
    if ((b.password !== undefined || b.active === false) && id !== me.id) await db.query("DELETE FROM entilaaqa.sessions WHERE user_id = $1", [id]);
    return res.json({ ok: true });
  }

  res.setHeader("Allow", "GET, POST, PATCH, DELETE");
  return res.status(405).json({ ok: false, error: "method_not_allowed" });
}
