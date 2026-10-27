const SESSION_COOKIE = "tankyutyan_session";
const STATE_COOKIE = "tankyutyan_oauth_state";
const SESSION_SECONDS = 8 * 60 * 60;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function redirect(url, cookie) {
  const headers = new Headers({
    Location: url,
    "Cache-Control": "no-store",
  });
  if (cookie) headers.append("Set-Cookie", cookie);
  return new Response(null, { status: 302, headers });
}

function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function readCookies(request) {
  const result = {};
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    result[part.slice(0, index).trim()] =
      part.slice(index + 1).trim();
  }
  return result;
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

function adminIds(env) {
  return new Set(
    (env.DISCORD_ADMIN_IDS || "")
      .split(",")
      .map(x => x.trim())
      .filter(Boolean)
  );
}

async function hmac(value, env) {
  if (!env.SESSION_SECRET) throw new Error("SESSION_SECRET is missing");
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(env.SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(value)
  );
  return base64url(new Uint8Array(signature));
}

async function makeSession(userId, env) {
  const payload = base64url(
    encoder.encode(JSON.stringify({
      uid: userId,
      exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS,
    }))
  );
  return `${payload}.${await hmac(payload, env)}`;
}

async function verifySession(request, env) {
  const token = readCookies(request)[SESSION_COOKIE];
  if (!token) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const [payload, signature] = parts;
  if (!safeEqual(signature, await hmac(payload, env).catch(() => ""))) {
    return null;
  }

  try {
    const data = JSON.parse(decoder.decode(fromBase64url(payload)));
    if (
      typeof data.uid !== "string" ||
      !adminIds(env).has(data.uid) ||
      !Number.isInteger(data.exp) ||
      data.exp <= Math.floor(Date.now() / 1000)
    ) return null;

    return { id: data.uid };
  } catch {
    return null;
  }
}

async function readJson(request) {
  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error("Content-Type must be application/json");
  }

  const raw = await request.text();
  if (encoder.encode(raw).byteLength > 262144) {
    throw new Error("Request body too large");
  }

  const data = JSON.parse(raw);
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Invalid JSON object");
  }
  return data;
}

function validUserId(id) {
  return typeof id === "string" && /^\d{17,20}$/.test(id);
}

async function requireAgent(request, env) {
  const supplied = request.headers.get("x-agent-secret") || "";
  return !!env.AGENT_SECRET &&
    safeEqual(supplied, env.AGENT_SECRET);
}

async function supabase(env, path, options = {}) {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("Supabase configuration is missing");
  }

  const base = env.SUPABASE_URL.replace(/\/+$/, "");
  const response = await fetch(`${base}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Supabase error: ${response.status} ${text.slice(0, 300)}`);
  }
  return text ? JSON.parse(text) : null;
}

function mapSettings(row) {
  return {
    botDisplayName: row.bot_display_name,
    searchEnabled: row.search_enabled,
    maxAnswerTokens: row.max_answer_tokens,
    maintenanceMode: row.maintenance_mode,
  };
}

async function readBotSettings(env) {
  const rows = await supabase(
    env,
    "bot_settings?id=eq.1&select=bot_display_name,search_enabled,max_answer_tokens,maintenance_mode"
  );
  if (!Array.isArray(rows) || !rows[0]) {
    throw new Error("Bot settings not found");
  }
  return mapSettings(rows[0]);
}

async function readUserPower(userId, env) {
  const rows = await supabase(
    env,
    `user_power_settings?user_id=eq.${encodeURIComponent(userId)}&select=user_id,reasoning_effort,updated_at&limit=1`
  );
  if (!Array.isArray(rows) || !rows[0]) {
    return {
      userId,
      reasoningEffort: "medium",
      updatedAt: null,
    };
  }
  return {
    userId: rows[0].user_id,
    reasoningEffort: rows[0].reasoning_effort,
    updatedAt: rows[0].updated_at,
  };
}

async function writeUserPower(userId, effort, env) {
  const rows = await supabase(
    env,
    "user_power_settings?on_conflict=user_id",
    {
      method: "POST",
      headers: {
        Prefer: "resolution=merge-duplicates,return=representation",
      },
      body: JSON.stringify({
        user_id: userId,
        reasoning_effort: effort,
        updated_at: new Date().toISOString(),
      }),
    }
  );
  const row = Array.isArray(rows) ? rows[0] : null;
  return row ? {
    userId: row.user_id,
    reasoningEffort: row.reasoning_effort,
    updatedAt: row.updated_at,
  } : { userId, reasoningEffort: effort };
}

async function writeBotSettings(data, env) {
  if (
    typeof data.botDisplayName !== "string" ||
    !data.botDisplayName.trim() ||
    data.botDisplayName.length > 50 ||
    typeof data.searchEnabled !== "boolean" ||
    !Number.isInteger(data.maxAnswerTokens) ||
    data.maxAnswerTokens < 100 ||
    data.maxAnswerTokens > 2000 ||
    typeof data.maintenanceMode !== "boolean"
  ) {
    throw new Error("Invalid settings");
  }

  const rows = await supabase(
    env,
    "bot_settings?id=eq.1",
    {
      method: "PATCH",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify({
        bot_display_name: data.botDisplayName.trim(),
        search_enabled: data.searchEnabled,
        max_answer_tokens: data.maxAnswerTokens,
        maintenance_mode: data.maintenanceMode,
        updated_at: new Date().toISOString(),
      }),
    }
  );

  if (!Array.isArray(rows) || !rows[0]) {
    throw new Error("Settings update returned no row");
  }
  return mapSettings(rows[0]);
}

function validStatus(data) {
  if (!data || typeof data.connected !== "boolean") return false;
  const time = Date.parse(data.updated_at);
  if (!Number.isFinite(time) || time > Date.now() + 30000) return false;
  if (
    data.latency_ms !== null &&
    (!Number.isFinite(data.latency_ms) || data.latency_ms < 0)
  ) return false;
  if (data.bot_user !== null && typeof data.bot_user !== "string") return false;
  if (
    data.guild_count !== null &&
    (!Number.isInteger(data.guild_count) || data.guild_count < 0)
  ) return false;
  return true;
}

function validStats(data) {
  const numeric = [
    "total", "success", "failed", "prompt_tokens",
    "completion_tokens", "total_tokens", "today_success",
  ];
  for (const key of numeric) {
    if (!Number.isSafeInteger(data[key]) || data[key] < 0) return false;
  }
  if (data.success + data.failed > data.total) return false;
  if (!Number.isFinite(data.success_rate) ||
      data.success_rate < 0 || data.success_rate > 100) return false;

  if (!Array.isArray(data.by_date) || data.by_date.length > 400) return false;
  if (!Array.isArray(data.by_model) || data.by_model.length > 100) return false;
  if (!Array.isArray(data.by_mode) || data.by_mode.length > 100) return false;

  for (const row of data.by_date) {
    if (
      !row || typeof row.date !== "string" ||
      !/^\d{4}-\d{2}-\d{2}$/.test(row.date) ||
      !Number.isSafeInteger(row.total) || row.total < 0 ||
      !Number.isSafeInteger(row.success) || row.success < 0 ||
      !Number.isSafeInteger(row.failed) || row.failed < 0 ||
      row.success + row.failed > row.total
    ) return false;
  }

  for (const list of [data.by_model, data.by_mode]) {
    for (const row of list) {
      if (
        !row || typeof row.label !== "string" ||
        !row.label.trim() || row.label.length > 200 ||
        !Number.isSafeInteger(row.count) || row.count < 0 ||
        !Number.isSafeInteger(row.success) || row.success < 0 ||
        !Number.isSafeInteger(row.failed) || row.failed < 0 ||
        row.success + row.failed > row.count
      ) return false;
    }
  }

  return data.updated_at === null ||
    (typeof data.updated_at === "string" &&
     Number.isFinite(Date.parse(data.updated_at)));
}

async function handle(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  const appOrigin = new URL(env.APP_ORIGIN).origin;
  const origin = request.headers.get("Origin");

  if (origin && origin !== appOrigin) {
    return json({ error: "Origin not allowed" }, 403);
  }

  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": appOrigin,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Vary": "Origin",
      },
    });
  }

  if (path === "/api/health" && method === "GET") {
    return json({ ok: true, service: "tankyutyan-worker" });
  }

  if (path === "/api/auth/discord" && method === "GET") {
    const stateBytes = crypto.getRandomValues(new Uint8Array(32));
    const state = base64url(stateBytes);

    await env.OAUTH_STATE.put(`oauth:${state}`, "1", {
      expirationTtl: 300,
    });

    const params = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      redirect_uri: env.DISCORD_CALLBACK_URL,
      response_type: "code",
      scope: "identify",
      state,
    });

    return redirect(
      `https://discord.com/oauth2/authorize?${params}`,
      cookie(STATE_COOKIE, state, 300)
    );
  }

  if (path === "/api/auth/callback" && method === "GET") {
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const stateCookie = readCookies(request)[STATE_COOKIE];

    if (
      !code || !state || !stateCookie ||
      !safeEqual(state, stateCookie)
    ) {
      return redirect(`${appOrigin}/?login=failed`,
        cookie(STATE_COOKIE, "", 0));
    }

    const stored = await env.OAUTH_STATE.get(`oauth:${state}`);
    await env.OAUTH_STATE.delete(`oauth:${state}`);

    if (!stored) {
      return redirect(`${appOrigin}/?login=failed`,
        cookie(STATE_COOKIE, "", 0));
    }

    const tokenResponse = await fetch(
      "https://discord.com/api/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          client_id: env.DISCORD_CLIENT_ID,
          client_secret: env.DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: env.DISCORD_CALLBACK_URL,
        }),
      }
    );

    if (!tokenResponse.ok) {
      return redirect(`${appOrigin}/?login=failed`,
        cookie(STATE_COOKIE, "", 0));
    }

    const tokenData = await tokenResponse.json();
    const userResponse = await fetch(
      "https://discord.com/api/users/@me",
      {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
        },
      }
    );

    if (!userResponse.ok) {
      return redirect(`${appOrigin}/?login=failed`,
        cookie(STATE_COOKIE, "", 0));
    }

    const user = await userResponse.json();
    if (!adminIds(env).has(user.id)) {
      return redirect(`${appOrigin}/?login=denied`,
        cookie(STATE_COOKIE, "", 0));
    }

    const session = await makeSession(user.id, env);
    const headers = new Headers({
      Location: appOrigin,
      "Cache-Control": "no-store",
    });
    headers.append("Set-Cookie", cookie(SESSION_COOKIE, session, SESSION_SECONDS));
    headers.append("Set-Cookie", cookie(STATE_COOKIE, "", 0));
    return new Response(null, { status: 302, headers });
  }

  if (path === "/api/auth/me" && method === "GET") {
    const user = await verifySession(request, env);
    return user ? json({ authenticated: true, user })
      : json({ authenticated: false }, 401);
  }

  if (path === "/api/auth/logout" && method === "POST") {
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Set-Cookie": cookie(SESSION_COOKIE, "", 0),
      },
    });
  }

  if (path.startsWith("/api/agent/")) {
    if (!(await requireAgent(request, env))) {
      return json({ error: "Unauthorized" }, 401);
    }

    if (path === "/api/agent/status" && method === "POST") {
      const data = await readJson(request);
      if (!validStatus(data)) return json({ error: "Invalid status" }, 400);
      await env.OAUTH_STATE.put("bot:status", JSON.stringify(data));
      return json({ ok: true });
    }

    if (path === "/api/agent/stats" && method === "POST") {
      const data = await readJson(request);
      if (!validStats(data)) return json({ error: "Invalid stats" }, 400);
      await env.OAUTH_STATE.put("bot:stats", JSON.stringify(data));
      return json({ ok: true });
    }

    if (path === "/api/agent/settings" && method === "GET") {
      return json(await readBotSettings(env));
    }

    if (path === "/api/agent/user-power" && method === "GET") {
      const userId = url.searchParams.get("user_id");
      if (!validUserId(userId)) return json({ error: "Invalid user_id" }, 400);
      return json(await readUserPower(userId, env));
    }

    if (path === "/api/agent/user-power" && method === "POST") {
      const data = await readJson(request);
      if (!validUserId(data.user_id)) {
        return json({ error: "Invalid user_id" }, 400);
      }
      if (!["low", "medium", "high"].includes(data.reasoning_effort)) {
        return json({ error: "Invalid reasoning_effort" }, 400);
      }
      return json(await writeUserPower(
        data.user_id, data.reasoning_effort, env
      ));
    }

    return json({ error: "Not found" }, 404);
  }

  if (path.startsWith("/api/")) {
    const user = await verifySession(request, env);
    if (!user) return json({ error: "Unauthorized" }, 401);

    if (path === "/api/bot/status" && method === "GET") {
      const raw = await env.OAUTH_STATE.get("bot:status");
      if (!raw) {
        return json({
          error: "まだ眠いよぉ…もう少し寝かせて…？",
        }, 503);
      }

      const data = JSON.parse(raw);
      const age = Date.now() - Date.parse(data.updated_at);
      if (age > 5 * 60 * 1000 || age < -30000) {
        return json({ ok: true, bot: { ...data, connected: false, stale: true } });
      }
      return json({ ok: true, bot: { ...data, stale: false } });
    }

    if (path === "/api/stats" && method === "GET") {
      const raw = await env.OAUTH_STATE.get("bot:stats");
      if (!raw) return json({ error: "Stats not available" }, 503);
      return json({
        ok: true,
        stats: JSON.parse(raw),
      });
    }

    if (path === "/api/settings" && method === "GET") {
      return json({
        ok: true,
        settings: await readBotSettings(env),
      });
    }

    if (path === "/api/settings" && method === "POST") {
      return json({
        ok: true,
        settings: await writeBotSettings(await readJson(request), env),
      });
    }

    return json({ error: "Not found" }, 404);
  }

  if (!env.ASSETS) return json({ error: "Assets binding missing" }, 500);
  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (error) {
      console.error("Worker error:", error);
      return json({ error: "Internal server error" }, 500);
    }
  },
};
