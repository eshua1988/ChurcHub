const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

async function ensureSchema(database) {
  await database.exec(`
    CREATE TABLE IF NOT EXISTS hub_cloud_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    INSERT OR IGNORE INTO hub_cloud_meta (key, value)
    VALUES ('schema_version', '1');
  `);
}

function json(body, init = {}) {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...CORS_HEADERS,
      ...(init.headers || {}),
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS_HEADERS });

    if (url.pathname === "/api/health") {
      try {
        await ensureSchema(env.HUB_DB);
        return json({ ok: true, service: "church-hub-api", storage: "r2", database: "d1" });
      } catch (error) {
        console.error("Cloud bootstrap failed", error);
        return json({ ok: false, error: "Cloud bootstrap failed" }, { status: 503 });
      }
    }
    return env.ASSETS.fetch(request);
  },
};