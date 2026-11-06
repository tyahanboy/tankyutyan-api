from pathlib import Path
import re
import sys

path = Path("server.control-test.js")
source = path.read_text(encoding="utf-8")

if "let latestBotStatus = null;" in source:
    print("中断: 受信機能がすでに追加されているようです。")
    sys.exit(1)

# 受信データをAPIプロセス内に保持する
marker = "const pendingStates = new Map();"
assert source.count(marker) == 1, "pendingStates の位置を特定できません"

source = source.replace(
    marker,
    marker + """

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
""",
    1,
)

# Bot専用の認証済みデータ受信口
marker = '''  try {
    if (req.method === "GET" &&
        url.pathname === "/" &&
        !url.search) {'''

assert source.count(marker) == 1, "ルーティング開始位置を特定できません"

agent_routes = r'''  try {
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
        !url.search) {'''

source = source.replace(marker, agent_routes, 1)

# 既存の管理画面用ルートを、受信データ参照方式に変更
pattern = re.compile(
    r'    if \(url\.pathname === "/api/bot/status" \|\|\s*'
    r'url\.pathname === "/api/stats"\) \{.*?'
    r'(?=    return sendJson\(res, 404, \{)',
    re.S,
)

replacement = r'''    if (url.pathname === "/api/bot/status" ||
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

'''

source, count = pattern.subn(replacement, source, count=1)
assert count == 1, "既存のステータス・統計ルートを安全に置き換えられません"

# 全置換が成功してからファイルに書き込む
path.write_text(source, encoding="utf-8")
print("API側の変更を適用しました。")
