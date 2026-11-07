import compression from "compression";
import express, { type NextFunction, type Request, type Response } from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { closeDb, startCleanup, warmUp } from "./db.js";
import bookings from "./routes/bookings.js";
import login from "./routes/login.js";
import me from "./routes/me.js";
import users from "./routes/users.js";

/* سيرفر Render: يقدّم الصفحات الثابتة من public/ ويشغّل مسارات /api (Express + PostgreSQL). */
const here = path.dirname(fileURLToPath(import.meta.url));
const pub = (name: string) => path.join(here, "..", "public", name);
const isProd = process.env.NODE_ENV === "production";

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1); // Render يضع بروكسي واحداً أمام التطبيق
app.use(compression());

app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'",
  );
  if (isProd) res.setHeader("Strict-Transport-Security", "max-age=31536000");
  next();
});

/* ---------- فحص الصحة (Render Health Check): خفيف ولا يلمس القاعدة ---------- */
app.get("/healthz", (_req, res) => res.type("text/plain").send("ok"));

/* ---------- API ---------- */
app.use("/api", express.json({ limit: "100kb" }));
// حماية CSRF إضافية: أي طلب يغيّر البيانات ويأتي من موقع آخر يُرفض.
app.use("/api", (req, res, next) => {
  const origin = req.headers.origin;
  if (req.method !== "GET" && origin) {
    try {
      if (new URL(origin).host !== req.headers.host) return res.status(403).json({ ok: false, error: "forbidden_origin" });
    } catch {
      return res.status(403).json({ ok: false, error: "forbidden_origin" });
    }
  }
  next();
});

// أي خطأ داخل المعالج يمرّ إلى معالج الأخطاء أدناه (يرجع JSON دائماً ولا يوقف السيرفر).
const wrap = (fn: (req: Request, res: Response) => unknown) => (req: Request, res: Response, next: NextFunction) =>
  Promise.resolve(fn(req, res)).catch(next);

app.all("/api/bookings", wrap(bookings));
app.all("/api/login", wrap(login));
app.all("/api/me", wrap(me));
app.all("/api/users", wrap(users));
app.use("/api", (_req, res) => res.status(404).json({ ok: false, error: "not_found" }));

/* ---------- الملفات الثابتة (قائمة بيضاء: لا يُكشف أي ملف آخر) ---------- */
app.get("/sw.js", (_req, res) => {
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Service-Worker-Allowed", "/");
  res.sendFile(pub("sw.js"));
});
app.get("/manifest.webmanifest", (_req, res) => {
  res.type("application/manifest+json");
  res.sendFile(pub("manifest.webmanifest"));
});
app.use("/icons", express.static(pub("icons"), { maxAge: "1d", index: false }));
app.get("/favicon.ico", (_req, res) => res.status(204).end());
app.get("/dashboard.html", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(pub("dashboard.html"));
});
app.get(["/", "/index.html"], (_req, res) => {
  res.setHeader("Cache-Control", "no-cache");
  res.sendFile(pub("index.html"));
});

/* ---------- 404 + معالج الأخطاء ---------- */
app.use((_req, res) => res.status(404).type("text/plain").send("Not found"));

app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) return next(err);
  if (err?.type === "entity.parse.failed") return res.status(400).json({ ok: false, error: "invalid_json" });
  if (err?.type === "entity.too.large") return res.status(413).json({ ok: false, error: "too_large" });
  if (err?.tag === "no_db_url" || err?.tag === "db_connect" || err?.tag === "db_schema") {
    console.error("database unavailable:", err.message);
    return res.status(503).json({ ok: false, error: "db" });
  }
  console.error(err);
  res.status(500).json({ ok: false, error: "server" });
});

/* ---------- التشغيل ---------- */
const port = Number(process.env.PORT) || 3000;
const server = app.listen(port, "0.0.0.0", () => console.log("Entilaaqa listening on " + port));

// لو كانت مهلة Node أقصر من مهلة بروكسي Render تظهر أخطاء 502 متقطعة.
server.keepAliveTimeout = 65_000;
server.headersTimeout = 66_000;

warmUp(); // تجهيز القاعدة في الخلفية دون تأخير فتح المنفذ
startCleanup();

// إيقاف آمن عند النشر الجديد (Render يرسل SIGTERM).
for (const sig of ["SIGTERM", "SIGINT"] as const) {
  process.on(sig, () => {
    console.log(sig + " received, shutting down");
    server.close(() => closeDb().finally(() => process.exit(0)));
    setTimeout(() => process.exit(0), 10_000).unref();
  });
}
process.on("unhandledRejection", (e) => console.error("unhandledRejection", e));
