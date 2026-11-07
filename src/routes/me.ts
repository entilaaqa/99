import type { Request, Response } from "express";
import { currentUser, destroySession } from "../auth.js";
import { getDb } from "../db.js";

const STATUSES = ["new", "contacted", "scheduled", "won", "lost"];
const COLS = "id,created_at,language,name,whatsapp,email,current_status,current_status_code,main_goal,biggest_challenge,monthly_income,monthly_income_code,ready_to_invest,ready_to_invest_code,session_start,session_tz,page_url,referrer,utm,country,lead_status,notes";

/*
  GET  /api/me             → المستخدم الحالي
  GET  /api/me?bookings=1  → الحجوزات
  POST /api/me?update=1    → تحديث حالة/ملاحظات عميل
  POST /api/me             → تسجيل الخروج
*/
export default async function me(req: Request, res: Response) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "GET" && req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ ok: false, error: "method_not_allowed" });
  }
  if (req.method === "POST" && req.query.update === undefined) {
    await destroySession(req, res);
    return res.status(200).json({ ok: true });
  }

  let user;
  try { user = await currentUser(req, res); } catch (e) {
    console.error("me: database unavailable", (e as Error).message);
    return res.status(503).json({ ok: false, error: "db" });
  }
  if (!user) return res.status(401).json({ ok: false });

  // الدور admin: كل الصلاحيات. الدور team: عرض + متابعة العملاء بدون تصدير وبدون إدارة المستخدمين.
  if (req.method === "GET" && req.query.bookings === undefined) {
    return res.status(200).json({ ok: true, email: user.email, isAdmin: user.isAdmin, canView: true });
  }
  const db = await getDb();

  if (req.method === "POST") {
    const b = req.body ?? {};
    const id = Number(b.id);
    const sets: string[] = [];
    const vals: unknown[] = [];
    if (b.lead_status !== undefined) {
      if (!STATUSES.includes(b.lead_status)) return res.status(400).json({ ok: false, error: "invalid_input" });
      vals.push(b.lead_status); sets.push(`lead_status = $${vals.length}`);
    }
    if (b.notes !== undefined) { vals.push(String(b.notes).slice(0, 2000)); sets.push(`notes = $${vals.length}`); }
    if (!Number.isInteger(id) || !sets.length) return res.status(400).json({ ok: false, error: "invalid_input" });
    vals.push(id);
    const r = await db.query(`UPDATE entilaaqa.bookings SET ${sets.join(", ")}, updated_at = now() WHERE id = $${vals.length}`, vals);
    if (!r.rowCount) return res.status(404).json({ ok: false, error: "not_found" });
    return res.status(200).json({ ok: true });
  }

  const { rows } = await db.query(`SELECT ${COLS} FROM entilaaqa.bookings ORDER BY created_at DESC LIMIT 2000`);
  return res.status(200).json({ ok: true, bookings: rows, migrated: true });
}
