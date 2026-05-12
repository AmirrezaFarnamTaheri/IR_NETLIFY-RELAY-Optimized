const VERSION = "1.1.0";
const GITHUB_PAGE = "https://ir-netlify.github.io/NETLIFY/";
const ROOT_PAGE_TTL_MS = 5 * 60 * 1000;
const UPSTREAM_TIMEOUT_MS = 30000;
const ROOT_PAGE_TIMEOUT_MS = 5000;
const MAX_X_HOST_LENGTH = 300;
const MAX_URL_LENGTH = 8192;
const RETRY_BACKOFF_MS = [100, 300];
const DNS_CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_DNS_CACHE_ENTRIES = 1024;
const DNS_CACHE_PRUNE_BATCH = 64;

const STRIP_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "forwarded",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cdn-loop",
]);

const STRIP_RESPONSE_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
]);

const BLOCKED_HOSTNAME_SUFFIXES = [
  ".localhost",
  ".local",
  ".localdomain",
  ".internal",
  ".home.arpa",
];

const CORS_ALLOWED_REQUEST_HEADERS = new Set([
  "accept",
  "accept-language",
  "authorization",
  "content-language",
  "content-type",
  "if-modified-since",
  "if-none-match",
  "range",
  "x-host",
]);

const SAFE_METHODS = new Set([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
]);

const RETRY_METHODS = new Set([
  "GET",
  "HEAD",
  "OPTIONS",
]);

const RETRY_STATUSES = new Set([
  502,
  503,
  504,
]);

const RESERVED_ROUTES = new Set([
  "/_relay/health",
  "/_relay/help",
  "/_relay/diagnostics",
  "/__relay-health",
  "/__relay-help",
  "/__relay-diagnostics",
]);

let cachedRootPage = null;
let cachedRootPageUntil = 0;
const dnsValidationCache = new Map();

class RelayError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = "RelayError";
    this.status = status;
    this.code = code;
  }
}

export default async function handler(request, context) {
  const startedAt = Date.now();
  const requestId = createRequestId();
  let targetInfo = null;
  let upstreamStatus = null;
  let responseStatus = 500;
  let errorCode = null;

  try {
    const url = new URL(request.url);

    if (request.url.length > MAX_URL_LENGTH) {
      throw new RelayError(414, "url_too_long", "Request URL is too long.");
    }

    if (RESERVED_ROUTES.has(url.pathname)) {
      const response = handleReservedRoute(request, url, requestId, startedAt, context);
      responseStatus = response.status;
      return response;
    }

    if (isRootPageRequest(request, url)) {
      const response = await handleRootPage(request, requestId, startedAt);
      responseStatus = response.status;
      return response;
    }

    if (isCorsPreflight(request)) {
      const response = withRelayHeaders(handleCorsPreflight(request), requestId, startedAt, {
        cache: "bypass",
      });
      responseStatus = response.status;
      return response;
    }

    if (!SAFE_METHODS.has(request.method.toUpperCase())) {
      throw new RelayError(405, "method_not_allowed", "HTTP method is not allowed.");
    }

    targetInfo = resolveTarget(request, url);
    await validateTarget(targetInfo, url);

    const upstream = await fetchUpstream(request, targetInfo.url);
    upstreamStatus = upstream.status;

    const response = buildProxyResponse(request, upstream, targetInfo, requestId, startedAt, context);
    responseStatus = response.status;
    return response;
  } catch (error) {
    const response = buildRelayError(error, requestId, startedAt);
    responseStatus = response.status;
    errorCode = getErrorCode(error);
    return response;
  } finally {
    logRequest({
      request,
      requestId,
      targetInfo,
      status: responseStatus,
      upstreamStatus,
      durationMs: Date.now() - startedAt,
      error: errorCode,
    });
  }
}

function createRequestId() {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  return `req_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function isRootPageRequest(request, url) {
  if (url.pathname !== "/") return false;
  if (request.headers.has("x-host")) return false;
  if (request.method !== "GET" && request.method !== "HEAD") return false;
  const upgradeHeader = request.headers.get("upgrade") || "";
  return upgradeHeader.toLowerCase() !== "websocket";
}

function isCorsPreflight(request) {
  return (
    request.method === "OPTIONS" &&
    request.headers.has("origin") &&
    request.headers.has("access-control-request-method")
  );
}

async function handleRootPage(request, requestId, startedAt) {
  let html = cachedRootPage;

  if (!html || Date.now() >= cachedRootPageUntil) {
    try {
      const response = await fetchWithTimeout(GITHUB_PAGE, {
        timeoutMs: ROOT_PAGE_TIMEOUT_MS,
        method: "GET",
      });
      html = await response.text();
      cachedRootPage = html;
      cachedRootPageUntil = Date.now() + ROOT_PAGE_TTL_MS;
    } catch {
      html = fallbackHelpHtml();
    }
  }

  const body = request.method === "HEAD" ? null : html;
  const response = new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=UTF-8",
      "cache-control": "public, max-age=300",
    },
  });

  return withRelayHeaders(response, requestId, startedAt, {
    cache: cachedRootPage === html ? "local" : "bypass",
  });
}

function handleReservedRoute(request, url, requestId, startedAt, context) {
  if (url.pathname.endsWith("/health") || url.pathname === "/_relay/health" || url.pathname === "/__relay-health") {
    return jsonResponse({
      ok: true,
      relay: "netlify-edge",
      version: VERSION,
    }, requestId, startedAt);
  }

  if (url.pathname.endsWith("/diagnostics") || url.pathname === "/_relay/diagnostics" || url.pathname === "/__relay-diagnostics") {
    return jsonResponse({
      ok: true,
      relay: "netlify-edge",
      version: VERSION,
      mode: "dynamic-x-host",
      streaming: true,
      cors: "same-origin-only",
      timeoutMs: UPSTREAM_TIMEOUT_MS,
      privateNetworkBlocking: getPrivateNetworkBlockingMode(),
      requestId,
      region: getRegion(context),
    }, requestId, startedAt);
  }

  const response = new Response(fallbackHelpHtml(), {
    status: 200,
    headers: {
      "content-type": "text/html; charset=UTF-8",
      "cache-control": "public, max-age=300",
    },
  });
  return withRelayHeaders(response, requestId, startedAt, { cache: "local" });
}

function jsonResponse(payload, requestId, startedAt, status = 200) {
  const response = new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store",
    },
  });
  return withRelayHeaders(response, requestId, startedAt, { cache: "bypass" });
}

function fallbackHelpHtml() {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Netlify Relay</title>
    <style>
      body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;padding:40px;line-height:1.55;color:#172033;background:#f8fafc}
      main{max-width:760px;margin:auto}
      code{background:#eef2f7;border-radius:4px;padding:2px 5px}
    </style>
  </head>
  <body>
    <main>
      <h1>Netlify Relay</h1>
      <p>The relay is deployed and ready. Generated clients should send an <code>x-host</code> header so requests can be forwarded to the selected upstream server.</p>
      <p>Local checks are available at <code>/_relay/health</code> and <code>/_relay/diagnostics</code>.</p>
    </main>
  </body>
</html>`;
}

function resolveTarget(request, incomingUrl) {
  const rawHeader = request.headers.get("x-host");

  if (!rawHeader) {
    throw new RelayError(400, "missing_x_host", "Error: x-host header is missing.");
  }

  const rawTarget = rawHeader.trim();

  if (!rawTarget) {
    throw new RelayError(400, "empty_x_host", "Error: x-host header is empty.");
  }

  if (rawTarget.length > MAX_X_HOST_LENGTH) {
    throw new RelayError(400, "x_host_too_long", "Error: x-host header is too long.");
  }

  if (/[\r\n\t]/.test(rawTarget)) {
    throw new RelayError(400, "invalid_x_host", "Error: x-host header contains invalid characters.");
  }

  let baseUrl;
  if (/^https?:\/\//i.test(rawTarget)) {
    baseUrl = parseTargetUrl(rawTarget);
    if (baseUrl.username || baseUrl.password) {
      throw new RelayError(400, "target_credentials_blocked", "Error: target credentials are not allowed.");
    }
    baseUrl.hash = "";
    baseUrl.search = "";
  } else if (rawTarget.includes("/") || rawTarget.includes("?") || rawTarget.includes("#")) {
    throw new RelayError(400, "invalid_x_host", "Error: x-host must be a hostname or URL.");
  } else {
    const protocol = inferProtocol(rawTarget);
    baseUrl = parseTargetUrl(`${protocol}${rawTarget}`);
  }

  if (baseUrl.protocol !== "http:" && baseUrl.protocol !== "https:") {
    throw new RelayError(400, "invalid_protocol", "Error: target protocol must be HTTP or HTTPS.");
  }

  const targetUrl = new URL(baseUrl.href);
  const basePath = targetUrl.pathname === "/" ? "" : targetUrl.pathname.replace(/\/+$/, "");
  targetUrl.pathname = `${basePath}${incomingUrl.pathname}`;
  targetUrl.search = incomingUrl.search;
  targetUrl.hash = "";

  return {
    url: targetUrl,
    host: targetUrl.host,
    hostname: targetUrl.hostname,
    protocol: targetUrl.protocol,
    baseHost: baseUrl.host,
  };
}

function parseTargetUrl(value) {
  try {
    return new URL(value);
  } catch {
    throw new RelayError(400, "invalid_x_host", "Error: x-host must be a valid URL or hostname.");
  }
}

function inferProtocol(host) {
  const lowerHost = host.toLowerCase();
  const isSecure =
    !lowerHost.includes(":") ||
    lowerHost.endsWith(":443") ||
    /^s\d+\./.test(lowerHost);
  return isSecure ? "https://" : "http://";
}

async function validateTarget(targetInfo, incomingUrl) {
  const targetHostname = normalizeHostname(targetInfo.hostname);
  const requestHostname = normalizeHostname(incomingUrl.hostname);

  if (!targetHostname) {
    throw new RelayError(400, "invalid_target", "Error: target host is invalid.");
  }

  if (targetHostname === requestHostname) {
    throw new RelayError(508, "relay_loop_blocked", "Error: target points back to this relay.");
  }

  if (isBlockedHostname(targetHostname)) {
    throw new RelayError(403, "private_target_blocked", "Error: private or local targets are blocked.");
  }

  if (isBlockedIpLiteral(targetHostname)) {
    throw new RelayError(403, "private_target_blocked", "Error: private or local targets are blocked.");
  }

  await assertPublicDnsTarget(targetHostname);
}

function isBlockedHostname(hostname) {
  if (BLOCKED_HOSTNAMES.has(hostname)) return true;
  return BLOCKED_HOSTNAME_SUFFIXES.some((suffix) => hostname.endsWith(suffix));
}

function normalizeHostname(hostname) {
  return String(hostname || "")
    .trim()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "")
    .toLowerCase();
}

function isBlockedIpLiteral(hostname) {
  if (isBlockedIpv4(hostname)) return true;
  if (isBlockedIpv6(hostname)) return true;
  return false;
}

function isIpLiteral(hostname) {
  return isIpv4Literal(hostname) || hostname.includes(":");
}

function isIpv4Literal(hostname) {
  const parts = hostname.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part));
}

function isBlockedIpv4(hostname) {
  const parts = hostname.split(".");
  if (parts.length !== 4) return false;
  if (!parts.every((part) => /^\d{1,3}$/.test(part))) return false;

  const nums = parts.map((part) => Number(part));
  if (!nums.every((num) => num >= 0 && num <= 255)) return true;

  const [a, b] = nums;
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true;
  return false;
}

function isBlockedIpv6(hostname) {
  const value = hostname.toLowerCase();
  if (!value.includes(":")) return false;
  if (value === "::1" || value === "0:0:0:0:0:0:0:1") return true;
  if (value.startsWith("fc") || value.startsWith("fd")) return true;
  if (value.startsWith("fe8") || value.startsWith("fe9") || value.startsWith("fea") || value.startsWith("feb")) return true;
  if (value.startsWith("::ffff:")) {
    return isBlockedIpv4(value.slice("::ffff:".length));
  }
  return false;
}

async function assertPublicDnsTarget(hostname) {
  if (isIpLiteral(hostname) || !canResolveDns()) return;

  const cachedResult = dnsValidationCache.get(hostname);
  if (cachedResult && cachedResult.expiresAt > Date.now()) {
    if (cachedResult.blocked) {
      throw new RelayError(403, "private_target_blocked", "Error: private or local targets are blocked.");
    }
    return;
  }

  const addresses = await resolveTargetAddresses(hostname);
  const blocked = addresses.some((address) => isBlockedIpLiteral(normalizeHostname(address)));
  pruneDnsValidationCache();
  dnsValidationCache.set(hostname, {
    blocked,
    expiresAt: Date.now() + DNS_CACHE_TTL_MS,
  });
  enforceDnsValidationCacheLimit();

  if (blocked) {
    throw new RelayError(403, "private_target_blocked", "Error: private or local targets are blocked.");
  }
}

function pruneDnsValidationCache() {
  const now = Date.now();
  let checked = 0;

  for (const [hostname, cachedResult] of dnsValidationCache) {
    if (cachedResult.expiresAt <= now) {
      dnsValidationCache.delete(hostname);
    }

    checked += 1;
    if (checked >= DNS_CACHE_PRUNE_BATCH) break;
  }
}

function enforceDnsValidationCacheLimit() {
  while (dnsValidationCache.size > MAX_DNS_CACHE_ENTRIES) {
    const oldestKey = dnsValidationCache.keys().next().value;
    if (!oldestKey) break;
    dnsValidationCache.delete(oldestKey);
  }
}

async function resolveTargetAddresses(hostname) {
  const addresses = [];

  for (const recordType of ["A", "AAAA"]) {
    try {
      const records = await Deno.resolveDns(hostname, recordType);
      addresses.push(...records);
    } catch {
      // DNS lookup failures should not turn valid public hosts into relay errors.
    }
  }

  return addresses;
}

function canResolveDns() {
  return typeof Deno !== "undefined" && typeof Deno.resolveDns === "function";
}

function getPrivateNetworkBlockingMode() {
  return canResolveDns() ? "dns-and-literal" : "literal-and-reserved-hostname";
}

async function fetchUpstream(request, targetUrl) {
  const method = request.method.toUpperCase();
  const headers = buildForwardHeaders(request);
  const fetchOptions = {
    timeoutMs: UPSTREAM_TIMEOUT_MS,
    method,
    headers,
    redirect: "manual",
    body: method !== "GET" && method !== "HEAD" ? request.body : undefined,
  };

  return fetchWithRetries(targetUrl.href, fetchOptions, method);
}

function buildForwardHeaders(request) {
  const headers = new Headers();
  let clientIp = null;

  for (const [key, value] of request.headers) {
    const lowerKey = key.toLowerCase();

    if (
      STRIP_REQUEST_HEADERS.has(lowerKey) ||
      lowerKey.startsWith("x-nf-") ||
      lowerKey.startsWith("x-netlify-") ||
      lowerKey === "x-host"
    ) {
      continue;
    }

    if (lowerKey === "x-real-ip" || lowerKey === "x-forwarded-for") {
      if (!clientIp) clientIp = value.split(",")[0].trim();
      continue;
    }

    headers.set(key, value);
  }

  if (clientIp) headers.set("x-forwarded-for", clientIp);
  return headers;
}

function fetchWithTimeout(input, options) {
  const { timeoutMs, ...fetchOptions } = options;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  return fetch(input, {
    ...fetchOptions,
    signal: controller.signal,
  }).finally(() => clearTimeout(timeout));
}

async function fetchWithRetries(input, options, method) {
  const canRetry = RETRY_METHODS.has(method);
  const maxAttempts = canRetry ? RETRY_BACKOFF_MS.length + 1 : 1;
  let lastError = null;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const response = await fetchWithTimeout(input, options);
      if (!canRetry || !RETRY_STATUSES.has(response.status) || attempt === maxAttempts - 1) {
        return response;
      }
      await releaseResponseBody(response);
    } catch (error) {
      lastError = error;
      if (!canRetry || attempt === maxAttempts - 1) {
        throw error;
      }
    }

    await sleep(RETRY_BACKOFF_MS[attempt]);
  }

  throw lastError || new Error("Upstream fetch failed.");
}

async function releaseResponseBody(response) {
  if (!response.body) return;

  try {
    await response.body.cancel();
  } catch {
    try {
      await response.arrayBuffer();
    } catch {
      // Best-effort resource release before retrying.
    }
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildProxyResponse(request, upstream, targetInfo, requestId, startedAt, context) {
  const responseHeaders = buildResponseHeaders(upstream, targetInfo, request);
  const body = request.method === "HEAD" ? null : upstream.body;

  const response = new Response(body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  });

  return withRelayHeaders(response, requestId, startedAt, {
    cache: "pass",
    upstreamStatus: upstream.status,
    targetHost: targetInfo.baseHost,
    region: getRegion(context),
  });
}

function buildResponseHeaders(upstream, targetInfo, request) {
  const responseHeaders = new Headers();

  for (const [key, value] of upstream.headers) {
    const lowerKey = key.toLowerCase();
    if (STRIP_RESPONSE_HEADERS.has(lowerKey)) continue;
    if (lowerKey === "set-cookie") continue;

    if (lowerKey === "location") {
      responseHeaders.set(key, rewriteLocationHeader(value, targetInfo, request));
      continue;
    }

    responseHeaders.set(key, value);
  }

  appendSetCookieHeaders(responseHeaders, upstream.headers, targetInfo);
  applyCorsHeaders(responseHeaders, request);
  return responseHeaders;
}

function rewriteLocationHeader(locationValue, targetInfo, request) {
  if (!locationValue) return locationValue;

  let locationUrl;
  try {
    locationUrl = new URL(locationValue, targetInfo.url);
  } catch {
    return locationValue;
  }

  const targetHost = normalizeHostname(targetInfo.url.hostname);
  const locationHost = normalizeHostname(locationUrl.hostname);
  if (locationHost !== targetHost) return locationValue;

  const relayUrl = new URL(request.url);
  relayUrl.pathname = locationUrl.pathname;
  relayUrl.search = locationUrl.search;
  relayUrl.hash = locationUrl.hash;
  return relayUrl.href;
}

function appendSetCookieHeaders(responseHeaders, upstreamHeaders, targetInfo) {
  const cookies = getSetCookieValues(upstreamHeaders);
  for (const cookie of cookies) {
    responseHeaders.append("set-cookie", rewriteSetCookie(cookie, targetInfo));
  }
}

function getSetCookieValues(headers) {
  if (typeof headers.getSetCookie === "function") {
    return headers.getSetCookie();
  }

  const cookie = headers.get("set-cookie");
  if (!cookie) return [];
  return splitCombinedSetCookie(cookie);
}

function splitCombinedSetCookie(headerValue) {
  const cookies = [];
  let start = 0;
  let inExpires = false;

  for (let index = 0; index < headerValue.length; index += 1) {
    const char = headerValue[index];
    const segment = headerValue.slice(Math.max(0, index - 8), index + 1).toLowerCase();

    if (segment.endsWith("expires=")) inExpires = true;
    if (inExpires && char === ";") inExpires = false;

    if (!inExpires && char === "," && /\s*[^=;,\s]+=/.test(headerValue.slice(index + 1, index + 80))) {
      cookies.push(headerValue.slice(start, index).trim());
      start = index + 1;
    }
  }

  cookies.push(headerValue.slice(start).trim());
  return cookies.filter(Boolean);
}

function rewriteSetCookie(cookie, targetInfo) {
  const targetHostname = normalizeHostname(targetInfo.hostname);
  return cookie
    .split(";")
    .map((part) => {
      const trimmed = part.trim();
      if (!/^domain=/i.test(trimmed)) return part;

      const cookieDomain = normalizeHostname(trimmed.slice("domain=".length));
      if (cookieDomain === targetHostname || targetHostname.endsWith(`.${cookieDomain}`)) {
        return "";
      }
      return part;
    })
    .filter((part) => part.trim())
    .join("; ");
}

function handleCorsPreflight(request) {
  if (!isTrustedCorsOrigin(request)) {
    return new Response(null, {
      status: 403,
      headers: {
        "cache-control": "no-store",
        "vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
      },
    });
  }

  const allowedHeaders = getAllowedCorsRequestHeaders(request);
  const responseHeaders = new Headers({
    "access-control-allow-methods": "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
    "access-control-allow-headers": allowedHeaders,
    "access-control-max-age": "86400",
    "cache-control": "public, max-age=86400",
    "vary": "Origin, Access-Control-Request-Method, Access-Control-Request-Headers",
  });

  applyCorsHeaders(responseHeaders, request);
  return new Response(null, { status: 204, headers: responseHeaders });
}

function applyCorsHeaders(headers, request) {
  if (!isTrustedCorsOrigin(request)) return;

  const origin = request.headers.get("origin");
  headers.set("access-control-allow-origin", origin);
  headers.set("access-control-allow-credentials", "true");
  appendVary(headers, "Origin");
}

function isTrustedCorsOrigin(request) {
  const origin = request.headers.get("origin");
  if (!origin || /[\r\n]/.test(origin)) return false;

  try {
    const originUrl = new URL(origin);
    const requestUrl = new URL(request.url);
    if (originUrl.protocol !== "https:" && originUrl.protocol !== "http:") return false;
    return normalizeHostname(originUrl.host) === normalizeHostname(requestUrl.host);
  } catch {
    return false;
  }
}

function getAllowedCorsRequestHeaders(request) {
  const requestedHeaders = request.headers.get("access-control-request-headers");
  if (!requestedHeaders) return "authorization, content-type, x-host";

  const allowedHeaders = requestedHeaders
    .split(",")
    .map((header) => header.trim().toLowerCase())
    .filter((header) => CORS_ALLOWED_REQUEST_HEADERS.has(header));

  return allowedHeaders.length ? allowedHeaders.join(", ") : "content-type";
}

function appendVary(headers, value) {
  const existing = headers.get("vary");
  if (!existing) {
    headers.set("vary", value);
    return;
  }

  const values = existing.split(",").map((item) => item.trim().toLowerCase());
  if (!values.includes(value.toLowerCase())) {
    headers.set("vary", `${existing}, ${value}`);
  }
}

function withRelayHeaders(response, requestId, startedAt, details = {}) {
  const headers = new Headers(response.headers);
  headers.set("x-relay-request-id", requestId);
  headers.set("x-relay-duration-ms", String(Date.now() - startedAt));
  headers.set("x-relay-version", VERSION);

  if (details.cache) headers.set("x-relay-cache", details.cache);
  if (details.upstreamStatus != null) headers.set("x-relay-upstream-status", String(details.upstreamStatus));
  if (details.targetHost) headers.set("x-relay-target-host", details.targetHost);
  if (details.region) headers.set("x-relay-region", details.region);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function buildRelayError(error, requestId, startedAt) {
  const status = getErrorStatus(error);
  const code = getErrorCode(error);
  const message = getErrorMessage(error, status);

  const response = new Response(message, {
    status,
    headers: {
      "content-type": "text/plain; charset=UTF-8",
      "cache-control": "no-store",
      "x-relay-error": code,
    },
  });

  return withRelayHeaders(response, requestId, startedAt, { cache: "bypass" });
}

function getErrorStatus(error) {
  if (error instanceof RelayError) return error.status;
  if (error && error.name === "AbortError") return 504;
  return 502;
}

function getErrorCode(error) {
  if (error instanceof RelayError) return error.code;
  if (error && error.name === "AbortError") return "upstream_timeout";
  return "upstream_fetch_failed";
}

function getErrorMessage(error, status) {
  if (error instanceof RelayError) return error.message;
  if (status === 504) return "Gateway Timeout: upstream did not respond in time.";
  return "Bad Gateway: relay could not reach the upstream target.";
}

function getRegion(context) {
  if (!context) return null;
  return context.server?.region || context.region || context.geo?.city || null;
}

function logRequest({ request, requestId, targetInfo, status, upstreamStatus, durationMs, error }) {
  try {
    const url = new URL(request.url);
    console.log(JSON.stringify({
      requestId,
      method: request.method,
      path: url.pathname,
      targetHost: targetInfo ? targetInfo.baseHost : null,
      status,
      upstreamStatus,
      durationMs,
      error,
    }));
  } catch {
    console.log(JSON.stringify({
      requestId,
      status,
      upstreamStatus,
      durationMs,
      error: error || "log_failed",
    }));
  }
}
