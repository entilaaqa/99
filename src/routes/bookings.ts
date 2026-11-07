import type { Request, Response } from "express";
import { randomUUID } from "node:crypto";
import { clientIp, limiter } from "../auth.js";
import { getDb } from "../db.js";

/*
  POST /api/bookings  → يحفظ حجز الفورم في PostgreSQL (Render).
  GET  /api/bookings  → فحص سريع لحالة الاتصال بالقاعدة (بدون أي بيانات حساسة).
*/

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const perIp = limiter(10, 60 * 60_000); // 10 حجوزات/ساعة لكل IP

const str = (v: unknown, max: number) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const opt = (v: unknown, max: number) => str(v, max) || null;
const choice = (v: unknown) => {
  const o = (v ?? {}) as { code?: unknown; label?: unknown };
  const code = Number(o.code);
  return { code: Number.isInteger(code) && code > 0 && code < 20 ? code : 0, label: str(o.label, 300) };
};
const bad = (res: Response, error: string) => res.status(400).json({ ok: false, error });

export default async function bookings(req: Request, res: Response) {
  if (req.method === "GET") {
    res.setHeader("Cache-Control", "no-store");
    try {
      await (await getDb()).query("SELECT 1");
      return res.status(200).json({ ok: true, db: "connected" });
    } catch (e) {
      const err = e as Error & { tag?: string; code?: string };
      console.error("db check failed:", err.message);
      return res.status(503).json({ ok: false, db: "failed", reason: err.tag || "unknown", code: err.code || null });
    }
  }
  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({ ok: false, error: "method_not_allowed" });
  }

  const body = req.body as Record<string, any> | undefined;
  if (!body || typeof body !== "object") return bad(res, "invalid_body");

  // Honeypot: البوتات تملأ الحقل المخفي. نردّ بنجاح وهمي ولا نحفظ شيئاً.
  if (str(body.website, 200)) return res.status(201).json({ ok: true });

  const ip = clientIp(req);
  if (perIp.blocked(ip)) return res.status(429).json({ ok: false, error: "too_many_requests" });

  const name = str(body.name, 200);
  const whatsapp = str(body.whatsapp, 32).replace(/[^\d+]/g, "");
  const email = str(body.email, 254).toLowerCase();
  const mainGoal = str(body.main_goal_12_months, 4000);
  const biggestChallenge = str(body.biggest_challenge, 4000);
  const status = choice(body.current_status);
  const income = choice(body.monthly_income);
  const ready = choice(body.ready_to_invest_over_10000);

  if (name.length < 2) return bad(res, "name");
  if (whatsapp.replace(/\D/g, "").length < 7) return bad(res, "whatsapp");
  if (!EMAIL.test(email)) return bad(res, "email");
  if (!mainGoal) return bad(res, "main_goal");
  if (!biggestChallenge) return bad(res, "biggest_challenge");
  if (!status.code || !income.code || !ready.code) return bad(res, "choices");

  const session = (body.session ?? {}) as Record<string, unknown>;
  const source = (body.source ?? {}) as Record<string, unknown>;
  const utm: Record<string, string> = {};
  if (source.utm && typeof source.utm === "object") {
    for (const [k, v] of Object.entries(source.utm as Record<string, unknown>).slice(0, 20)) {
      if (/^[a-z_]{2,40}$/i.test(k)) utm[k] = str(v, 300);
    }
  }

  const bookingId = typeof body.booking_id === "string" && UUID.test(body.booking_id) ? body.booking_id : randomUUID();
  const language = ["ar", "en", "zh"].includes(body.language) ? body.language : "ar";
  const country = req.headers["cf-ipcountry"];

  perIp.hit(ip);
  try {
    const db = await getDb();
    // إعادة إرسال نفس booking_id تُحفظ مرة واحدة فقط.
    await db.query(
      `INSERT INTO entilaaqa.bookings
         (booking_id, language, name, whatsapp, email, current_status, current_status_code, main_goal, biggest_challenge,
          monthly_income, monthly_income_code, ready_to_invest, ready_to_invest_code,
          session_start, session_end, session_tz, page_url, referrer, utm, user_agent, country)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20,$21)
       ON CONFLICT (booking_id) DO NOTHING`,
      [
        bookingId, language, name, whatsapp, email, status.label, status.code, mainGoal, biggestChallenge,
        income.label, income.code, ready.label, ready.code,
        opt(session.start, 64), opt(session.end, 64), opt(session.tz, 64),
        opt(source.page_url, 2000), opt(source.referrer, 2000), JSON.stringify(utm),
        opt(req.headers["user-agent"], 500), typeof country === "string" ? country.slice(0, 8) : null,
      ],
    );
  } catch (e) {
    const err = e as Error & { tag?: string; code?: string };
    console.error("Failed to save booking:", err.message);
    return res.status(500).json({ ok: false, error: err.tag || "server", code: err.code || null });
  }
  return res.status(201).json({ ok: true, booking_id: bookingId });
}
