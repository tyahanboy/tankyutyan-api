import { enqueueAction, listActions } from "./control-queue/queue.js";
import http from "node:http";
import fs from "node:fs/promises";
import {
  randomBytes,
  createHmac,
  timingSafeEqual
} from "node:crypto";

const PORT = Number(process.env.PORT || process.env.AUTH_TEST_PORT) || 3001;
const HOST = process.env.HOST || "127.0.0.1";
const HOME = process.env.HOME || "";
const BOT_STATUS_FILE = `${HOME}/discord-bot/bot_status.json`;
const USAGE_LOG_FILE = `${HOME}/discord-bot/usage_log.csv`;
const STALE_AFTER_MS = 5 * 60 * 1000;

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const AGENT_SECRET = process.env.AGENT_SECRET;
const ADMIN_IDS = new Set(
  (process.env.DISCORD_ADMIN_IDS || "")
    .split(",").map(v => v.trim()).filter(Boolean)
);
const APP_ORIGIN = process.env.APP_ORIGIN;
const CALLBACK_URL =
  process.env.DISCORD_CALLBACK_URL ||
  "http://127.0.0.1:3001/api/auth/callback";
const SESSION_SECONDS = 8 * 60 * 60;
const COOKIE_NAME = "tankyutyan_session";
const STATE_COOKIE = "tankyutyan_oauth_state";
const pendingStates = new Map();

// Botから受信した最新データ。Render再起動後はBotから再送信する。
let latestBotStatus = null;
let latestUsageStats = null;

async function readJsonBody(req, maxBytes = 262144) {
  const chunks = [];
  let size = 0;

  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) {
      throw new Error("Request body too large");
    }
    chunks.push(chunk);
  }

  const parsed = JSON.parse(
    Buffer.concat(chunks).toString("utf8")
  );

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Invalid JSON object");
  }

  return parsed;
}


if (!AGENT_SECRET || !/^[a-f0-9]{64}$/i.test(AGENT_SECRET)) throw new Error("AGENT_SECRETの設定が不正です");
if (!CLIENT_ID || !CLIENT_SECRET || !SESSION_SECRET ||
    !ADMIN_IDS.size || !APP_ORIGIN) {
  throw new Error("認証用環境変数が不足しています");
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(JSON.stringify(data));
}

function cookieOptions(maxAge = 0, sameSite = "Lax") {
  const secure = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  if (sameSite === "None" && !secure) {
    throw new Error("SameSite=NoneにはSecureが必要です");
  }
  return `Path=/; HttpOnly; SameSite=${sameSite}; Max-Age=${maxAge}${secure}`;
}

function sign(value) {
  return createHmac("sha256", SESSION_SECRET)
    .update(value).digest("base64url");
}

function safeEqual(a, b) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

function readCookies(req) {
  const result = {};
  for (const part of (req.headers.cookie || "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) {
      result[part.slice(0, index).trim()] =
        part.slice(index + 1).trim();
    }
  }
  return result;
}

function makeSession(userId) {
  const payload = Buffer.from(JSON.stringify({
    uid: userId,
    exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS
  })).toString("base64url");
  return `${payload}.${sign(payload)}`;
}

function verifySession(req) {
  const token = readCookies(req)[COOKIE_NAME];
  if (!token) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [payload, signature] = parts;
  if (!safeEqual(sign(payload), signature)) return null;

  try {
    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );
    if (typeof session.uid !== "string" ||
        !ADMIN_IDS.has(session.uid) ||
        !Number.isFinite(session.exp) ||
        session.exp <= Math.floor(Date.now() / 1000)) {
      return null;
    }
    return { id: session.uid };
  } catch {
    return null;
  }
}

function redirect(res, location, cookies = []) {
  res.writeHead(302, {
    Location: location,
    "Cache-Control": "no-store",
    "Set-Cookie": cookies
  });
  res.end();
}

function parseCsvLine(line) {
  const result = [];
  let field = "";
  let quoted = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (quoted && line[i + 1] === '"') {
        field += '"';
        i++;
      } else {
        quoted = !quoted;
      }
    } else if (ch === "," && !quoted) {
      result.push(field);
      field = "";
    } else {
      field += ch;
    }
  }
  result.push(field);
  return result;
}

async function readUsageStats() {
  const raw = await fs.readFile(USAGE_LOG_FILE, "utf8");
  const lines = raw.trim().split(/\r?\n/);

  if (lines.length < 2) {
    return {
      total: 0, success: 0, failed: 0, success_rate: 0,
      today_success: 0, by_date: [], by_model: [], by_mode: [],
      updated_at: null
    };
  }

  const headers = parseCsvLine(lines[0]);
  const rows = lines.slice(1).filter(line => line.trim()).map(line => {
    const values = parseCsvLine(line);
    return Object.fromEntries(
      headers.map((header, index) => [header, values[index] ?? ""])
    );
  });

  const success = rows.filter(row => row.status === "success").length;
  const failed = rows.filter(row => row.status === "failed").length;
  const today = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Tokyo", year: "numeric",
    month: "2-digit", day: "2-digit"
  }).format(new Date());

  const countBy = key => {
    const counts = new Map();
    for (const row of rows) {
      const label = row[key] || "unknown";
      const current = counts.get(label) ||
        { count: 0, success: 0, failed: 0 };
      current.count++;
      if (row.status === "success") current.success++;
      if (row.status === "failed") current.failed++;
      counts.set(label, current);
    }
    return [...counts.entries()]
      .map(([label, value]) => ({ label, ...value }))
      .sort((a, b) => a.label.localeCompare(b.label));
  };

  const byDate = new Map();
  for (const row of rows) {
    const date = row.date_jst || "unknown";
    const item = byDate.get(date) ||
      { date, total: 0, success: 0, failed: 0 };
    item.total++;
    if (row.status === "success") item.success++;
    if (row.status === "failed") item.failed++;
    byDate.set(date, item);
  }

  return {
    total: rows.length,
    success,
    failed: rows.filter(row => row.status !== "success").length,
    success_rate: rows.length
      ? Math.round(success / rows.length * 100) : 0,
    today_success: rows.filter(
      row => row.date_jst === today && row.status === "success"
    ).length,
    by_date: [...byDate.values()].sort(
      (a, b) => a.date.localeCompare(b.date)
    ),
    by_model: countBy("model"),
    by_mode: countBy("mode"),
    updated_at: rows.at(-1)?.timestamp_jst || null
  };
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;

  // Allow only the deployed portal origin.
  if (origin === APP_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", APP_ORIGIN);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Vary", "Origin");
  }

  // Reject browser requests from unapproved origins.
  if (origin && origin !== APP_ORIGIN) {
    return sendJson(res, 403, { ok: false, message: "Origin not allowed" });
  }

  if (req.method === "OPTIONS") {
    if (origin !== APP_ORIGIN) {
      return sendJson(res, 403, { ok: false });
    }
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url || "/", "http://127.0.0.1");

  try {
    if (
      req.method === "POST" &&
      (url.pathname === "/api/agent/status" ||
       url.pathname === "/api/agent/stats")
    ) {
      const suppliedSecret = req.headers["x-agent-secret"];

      if (
        typeof suppliedSecret !== "string" ||
        !safeEqual(suppliedSecret, AGENT_SECRET)
      ) {
        return sendJson(res, 401, { ok: false });
      }

      const contentType = String(req.headers["content-type"] || "")
        .split(";")[0].trim().toLowerCase();

      if (contentType !== "application/json") {
        return sendJson(res, 415, {
          ok: false, message: "JSONが必要だよ"
        });
      }

      let body;
      try {
        body = await readJsonBody(req);
      } catch {
        return sendJson(res, 400, {
          ok: false, message: "送信データを読み取れなかったよ"
        });
      }

      if (url.pathname === "/api/agent/status") {
        const updatedMs = typeof body.updated_at === "string"
          ? Date.parse(body.updated_at) : NaN;

        if (
          typeof body.connected !== "boolean" ||
          !Number.isFinite(updatedMs) ||
          updatedMs > Date.now() + 30000 ||
          !(
            body.latency_ms === null ||
            (typeof body.latency_ms === "number" &&
             Number.isFinite(body.latency_ms) &&
             body.latency_ms >= 0)
          ) ||
          !(
            body.bot_user === null ||
            typeof body.bot_user === "string"
          ) ||
          !(
            body.guild_count === null ||
            (Number.isInteger(body.guild_count) &&
             body.guild_count >= 0)
          )
        ) {
          return sendJson(res, 400, {
            ok: false, message: "Bot状態の形式が正しくないよ"
          });
        }

        latestBotStatus = {
          connected: body.connected,
          latency_ms: body.latency_ms,
          bot_user: body.bot_user,
          guild_count: body.guild_count,
          updated_at: body.updated_at
        };

        return sendJson(res, 200, { ok: true });
      }

      const requiredCounts = [
        "total", "success", "failed", "today_success"
      ];

      if (
        !requiredCounts.every(
          key => Number.isSafeInteger(body[key]) && body[key] >= 0
        ) ||
        typeof body.success_rate !== "number" ||
        !Number.isFinite(body.success_rate) ||
        body.success_rate < 0 ||
        body.success_rate > 100 ||
        !Array.isArray(body.by_date) ||
        !Array.isArray(body.by_model) ||
        !Array.isArray(body.by_mode) ||
        body.by_date.length > 400 ||
        body.by_model.length > 100 ||
        body.by_mode.length > 100 ||
        !body.by_date.every(item =>
          item && typeof item === "object" && !Array.isArray(item) &&
          typeof item.date === "string" &&
          /^\\d{4}-\\d{2}-\\d{2}$/.test(item.date) &&
          ["total", "success", "failed"].every(key =>
            Number.isSafeInteger(item[key]) && item[key] >= 0
          ) &&
          item.success + item.failed <= item.total
        ) ||
        ![body.by_model, body.by_mode].every(items =>
          items.every(item =>
            item && typeof item === "object" && !Array.isArray(item) &&
            typeof item.label === "string" &&
            item.label.length > 0 && item.label.length <= 200 &&
            ["count", "success", "failed"].every(key =>
              Number.isSafeInteger(item[key]) && item[key] >= 0
            ) &&
            item.success + item.failed <= item.count
          )
        ) ||
        !(
          body.updated_at === null ||
          (typeof body.updated_at === "string" &&
           Number.isFinite(Date.parse(body.updated_at)))
        )
      ) {
        return sendJson(res, 400, {
          ok: false, message: "統計データの形式が正しくないよ"
        });
      }

      latestUsageStats = {
        total: body.total,
        success: body.success,
        failed: body.failed,
        success_rate: body.success_rate,
        today_success: body.today_success,
        by_date: body.by_date,
        by_model: body.by_model,
        by_mode: body.by_mode,
        updated_at: body.updated_at
      };

      return sendJson(res, 200, { ok: true });
    }

    if (req.method === "GET" &&
        url.pathname === "/" &&
        !url.search) {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"
      });

      return res.end(`<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="google-site-verification" content="CKjZbcTBaogKgKE-nycZGDxFNKRTb_oibeMwMumtH8g">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>たんきゅーちゃん API</title>
</head>
<body>
  <h1>たんきゅーちゃん API</h1>
  <p>API service is running.</p>
</body>
</html>`);
    }
    if (req.method === "GET" &&
        url.pathname === "/api/health") {
      return sendJson(res, 200, {
        ok: true, service: "tankyutyan-auth-test"
      });
    }

    if (req.method === "GET" &&
        url.pathname === "/api/auth/discord") {
      const state = randomBytes(32).toString("hex");
      pendingStates.set(state, Date.now() + 5 * 60 * 1000);

      for (const [key, expiry] of pendingStates) {
        if (expiry < Date.now()) pendingStates.delete(key);
      }

      const authorize = new URL(
        "https://discord.com/oauth2/authorize"
      );
      authorize.searchParams.set("client_id", CLIENT_ID);
      authorize.searchParams.set("redirect_uri", CALLBACK_URL);
      authorize.searchParams.set("response_type", "code");
      authorize.searchParams.set("scope", "identify");
      authorize.searchParams.set("state", state);

      return redirect(res, authorize.toString(), [
        `${STATE_COOKIE}=${state}; ${cookieOptions(300)}`
      ]);
    }

    if (req.method === "GET" &&
        url.pathname === "/api/auth/callback") {
      const state = url.searchParams.get("state") || "";
      const code = url.searchParams.get("code") || "";
      const cookieState = readCookies(req)[STATE_COOKIE] || "";
      const expiry = pendingStates.get(state);
      pendingStates.delete(state);

      const clearState =
        `${STATE_COOKIE}=; ${cookieOptions(0)}`;

      if (!state || !code || !cookieState ||
          !safeEqual(state, cookieState) ||
          !expiry || expiry < Date.now()) {
        return redirect(res, `${APP_ORIGIN}/?login=failed`, [
          clearState
        ]);
      }

      const tokenResponse = await fetch(
        "https://discord.com/api/oauth2/token",
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            grant_type: "authorization_code",
            code,
            redirect_uri: CALLBACK_URL
          }),
          signal: AbortSignal.timeout(10000)
        }
      );

      if (!tokenResponse.ok) {
        return redirect(res, `${APP_ORIGIN}/?login=failed`, [
          clearState
        ]);
      }

      const tokenData = await tokenResponse.json();
      if (typeof tokenData.access_token !== "string") {
        return redirect(res, `${APP_ORIGIN}/?login=failed`, [
          clearState
        ]);
      }

      const userResponse = await fetch(
        "https://discord.com/api/users/@me",
        {
          headers: {
            Authorization: `Bearer ${tokenData.access_token}`
          },
          signal: AbortSignal.timeout(10000)
        }
      );

      if (!userResponse.ok) {
        return redirect(res, `${APP_ORIGIN}/?login=failed`, [
          clearState
        ]);
      }

      const user = await userResponse.json();
      if (typeof user.id !== "string" || !ADMIN_IDS.has(user.id)) {
        return redirect(res, `${APP_ORIGIN}/?login=denied`, [
          clearState,
          `${COOKIE_NAME}=; ${cookieOptions(0)}`
        ]);
      }

      const session = makeSession(user.id);
      return redirect(res, APP_ORIGIN, [
        clearState,
        `${COOKIE_NAME}=${session}; ${cookieOptions(SESSION_SECONDS, "None")}`
      ]);
    }

    if (req.method === "GET" &&
        url.pathname === "/api/auth/me") {
      const user = verifySession(req);
      if (!user) {
        return sendJson(res, 401, { ok: false, user: null });
      }
      return sendJson(res, 200, {
        ok: true, user: { id: user.id }
      });
    }

    if (req.method === "POST" &&
        url.pathname === "/api/auth/logout") {
      const origin = req.headers.origin;
      if (origin && origin !== APP_ORIGIN) {
        return sendJson(res, 403, { ok: false });
      }
      res.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Set-Cookie": `${COOKIE_NAME}=; ${cookieOptions(0, "None")}`,
        "X-Content-Type-Options": "nosniff"
      });
      return res.end(JSON.stringify({ ok: true }));
    }

    if (url.pathname === "/api/bot/status" ||
        url.pathname === "/api/stats") {
      if (!verifySession(req)) {
        return sendJson(res, 401, {
          ok: false, message: "ログインが必要だよ"
        });
      }
    }

    if (req.method === "GET" &&
        url.pathname === "/api/bot/status") {
      const status = latestBotStatus;

      if (!status) {
        return sendJson(res, 503, {
          ok: false, bot: null,
          message: "まだ眠いよぉ…もう少し寝かせて…？"
        });
      }

      const updatedAt = Date.parse(status.updated_at);
      const stale = !Number.isFinite(updatedAt) ||
        Date.now() - updatedAt > STALE_AFTER_MS ||
        updatedAt > Date.now() + 30000;

      return sendJson(res, 200, {
        ok: true,
        bot: {
          connected: status.connected === true && !stale,
          stale,
          latency_ms: status.latency_ms,
          bot_user: status.bot_user,
          guild_count: status.guild_count,
          updated_at: status.updated_at
        }
      });
    }

    if (req.method === "GET" && url.pathname === "/api/stats") {
      if (!latestUsageStats) {
        return sendJson(res, 503, {
          ok: false, message: "利用統計をまだ受信していないよ"
        });
      }

      return sendJson(res, 200, {
        ok: true, stats: latestUsageStats
      });
    }

    return sendJson(res, 404, {
      ok: false, message: "そのAPIはまだないよ"
    });
  } catch {
    return sendJson(res, 500, {
      ok: false, message: "認証APIでエラーが発生したよ"
    });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`認証テストAPI起動: http://${HOST}:${PORT}`);
});
