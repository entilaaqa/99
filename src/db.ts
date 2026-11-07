import pg from "pg";
import { hashPassword, verifyPassword } from "./password.js";

/* اتصال PostgreSQL على Render + إنشاء الجداول تلقائياً (idempotent) + حساب المدير الأول. */

// timestamptz و bigint كما هي (لا تحويلات مفاجئة): count(*) نحوّله صراحةً إلى ::int في الاستعلامات.
const SCHEMA = `
CREATE SCHEMA IF NOT EXISTS entilaaqa;

CREATE TABLE IF NOT EXISTS entilaaqa.bookings (
  id                   serial PRIMARY KEY,
  booking_id           uuid NOT NULL UNIQUE,
  created_at           timestamptz NOT NULL DEFAULT now(),
  language             text NOT NULL,
  name                 text NOT NULL,
  whatsapp             text NOT NULL,
  email                text NOT NULL,
  current_status       text NOT NULL,
  current_status_code  integer NOT NULL,
  main_goal            text NOT NULL,
  biggest_challenge    text NOT NULL,
  monthly_income       text NOT NULL,
  monthly_income_code  integer NOT NULL,
  ready_to_invest      text NOT NULL,
  ready_to_invest_code integer NOT NULL,
  session_start        text,
  session_end          text,
  session_tz           text,
  page_url             text,
  referrer             text,
  utm                  jsonb NOT NULL DEFAULT '{}',
  user_agent           text,
  country              text,
  lead_status          text NOT NULL DEFAULT 'new',
  notes                text,
  updated_at           timestamptz
);
ALTER TABLE entilaaqa.bookings ADD COLUMN IF NOT EXISTS lead_status text NOT NULL DEFAULT 'new';
ALTER TABLE entilaaqa.bookings ADD COLUMN IF NOT EXISTS notes text;
ALTER TABLE entilaaqa.bookings ADD COLUMN IF NOT EXISTS updated_at timestamptz;
CREATE INDEX IF NOT EXISTS bookings_created_at_idx ON entilaaqa.bookings (created_at DESC);

CREATE TABLE IF NOT EXISTS entilaaqa.users (
  id            serial PRIMARY KEY,
  email         text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  role          text NOT NULL DEFAULT 'team' CHECK (role IN ('admin','team')),
  active        boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz
);

CREATE TABLE IF NOT EXISTS entilaaqa.sessions (
  token_hash text PRIMARY KEY,
  user_id    integer NOT NULL REFERENCES entilaaqa.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  renewed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON entilaaqa.sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON entilaaqa.sessions (expires_at);
`;

/**
 * Render:
 *  - الرابط الداخلي (Internal): المضيف بلا نقاط (dpg-xxxx-a) ولا يحتاج SSL.
 *  - الرابط الخارجي (External): المضيف فيه نقاط (…-postgres.render.com) ويتطلب SSL.
 * نبني الإعدادات يدوياً لتجنّب تحذيرات sslmode في مكتبة pg.
 */
export function poolConfig(raw: string): pg.PoolConfig {
  const u = new URL(raw);
  const mode = (u.searchParams.get("sslmode") || process.env.PGSSLMODE || "").toLowerCase();
  const external = u.hostname.includes(".");
  const ssl = mode === "disable" ? false : mode ? { rejectUnauthorized: false } : external ? { rejectUnauthorized: false } : false;
  return {
    host: u.hostname,
    port: Number(u.port) || 5432,
    user: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    database: decodeURIComponent(u.pathname.slice(1)) || "postgres",
    ssl,
    max: 5,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
    keepAlive: true,
  };
}

let pool: pg.Pool | null = null;
let ready: Promise<pg.Pool> | null = null;

async function bootstrapAdmin(db: pg.Pool) {
  const email = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || "";
  if (!email && !password) return;
  if (!email || password.length < 10) {
    console.warn("ADMIN_EMAIL/ADMIN_PASSWORD: يجب ضبط البريد وكلمة مرور من 10 أحرف على الأقل. تم تخطي إنشاء المدير.");
    return;
  }
  const { rows } = await db.query("SELECT id, password_hash, role, active FROM entilaaqa.users WHERE email = $1", [email]);
  if (!rows.length) {
    await db.query("INSERT INTO entilaaqa.users (email, password_hash, role) VALUES ($1, $2, 'admin')", [email, await hashPassword(password)]);
    console.log("Admin user created:", email);
    return;
  }
  const u = rows[0];
  const same = await verifyPassword(password, u.password_hash);
  if (!same || u.role !== "admin" || !u.active) {
    await db.query("UPDATE entilaaqa.users SET password_hash = $2, role = 'admin', active = true WHERE id = $1", [u.id, same ? u.password_hash : await hashPassword(password)]);
    if (!same) await db.query("DELETE FROM entilaaqa.sessions WHERE user_id = $1", [u.id]); // تغيير كلمة المرور يُنهي الجلسات القديمة
    console.log("Admin user updated:", email);
  }
}

async function init(): Promise<pg.Pool> {
  const url = process.env.DATABASE_URL;
  if (!url) throw Object.assign(new Error("DATABASE_URL is not set"), { tag: "no_db_url" });
  const p = new pg.Pool(poolConfig(url));
  p.on("error", (e) => console.error("pg pool error", e));
  const client = await p.connect().catch((e) => {
    p.end().catch(() => {});
    throw Object.assign(e, { tag: "db_connect" });
  });
  try {
    // قفل استشاري: لو شغّلت Render نسختين معاً أثناء النشر لا يتعارض إنشاء الجداول.
    await client.query("SELECT pg_advisory_lock(727274)");
    try {
      await client.query(SCHEMA);
    } finally {
      await client.query("SELECT pg_advisory_unlock(727274)").catch(() => {});
    }
  } catch (e) {
    client.release();
    p.end().catch(() => {});
    throw Object.assign(e as Error, { tag: "db_schema" });
  }
  client.release();
  await bootstrapAdmin(p).catch((e) => console.error("bootstrapAdmin failed", e));
  await p.query("DELETE FROM entilaaqa.sessions WHERE expires_at < now()").catch(() => {});
  pool = p;
  return p;
}

/** يرجع الـ Pool بعد التأكد من الجداول. عند الفشل يُعاد المحاولة في الطلب التالي. */
export function getDb(): Promise<pg.Pool> {
  if (pool) return Promise.resolve(pool);
  if (!ready) {
    ready = init().catch((e) => {
      ready = null;
      throw e;
    });
  }
  return ready;
}

/** يُستدعى عند الإقلاع لتجهيز القاعدة مبكراً مع إعادة محاولة (مثلاً أثناء استيقاظ القاعدة). */
export async function warmUp() {
  for (let i = 1; i <= 6; i++) {
    try {
      await getDb();
      console.log("Database ready");
      return;
    } catch (e) {
      console.error(`Database not ready (attempt ${i}/6):`, (e as Error).message);
      await new Promise((r) => setTimeout(r, 5_000 * i));
    }
  }
}

export async function closeDb() {
  await pool?.end().catch(() => {});
  pool = null;
}

/** تنظيف الجلسات المنتهية كل ساعة. */
export function startCleanup() {
  setInterval(() => {
    pool?.query("DELETE FROM entilaaqa.sessions WHERE expires_at < now()").catch(() => {});
  }, 3_600_000).unref();
}
