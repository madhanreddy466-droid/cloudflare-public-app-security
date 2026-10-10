const hits = new Map();
const LIMIT = 10;        // max requests
const WINDOW_MS = 10000; // per 10 seconds

export async function onRequest({ request, next }) {
  const url = new URL(request.url);
  const path = url.pathname.toLowerCase();
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  // Policy 1: block unneeded HTTP methods
  if (["TRACE", "TRACK"].includes(request.method)) {
    return new Response("Blocked: method not allowed", { status: 405 });
  }

  // Policy 2: deny suspicious admin/probe paths
  const blockedPaths = ["/wp-admin", "/wp-login.php", "/.env", "/.git", "/phpmyadmin"];
  if (blockedPaths.some((p) => path.startsWith(p))) {
    return new Response("Blocked: suspicious path", { status: 403 });
  }

  // Policy 3: block the demo test marker in the query string
  if (url.search.includes("security_test_block")) {
    return new Response("Blocked: suspicious parameter", { status: 403 });
  }

  // Policy 4: simple per-IP rate limit
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < WINDOW_MS);
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) hits.clear(); // keep memory bounded
  if (recent.length > LIMIT) {
    return new Response("Too many requests", {
      status: 429,
      headers: { "Retry-After": "10" },
    });
  }

  return next();
}
