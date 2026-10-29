// JaatFlix video Worker - carries the video bytes so the main server's data limit is not used.
//
// Settings (Worker -> Settings -> Variables and Secrets):
//   LINK_SECRET   (required, Secret)  the SAME value as LINK_SECRET on the main server
//   ALLOW_ORIGIN  (recommended)       your site, e.g. https://jaatflix.blitz.cloud  (comma separated for more)
//   IP_CHECK      optional   "0" = do not compare the visitor IP with the link's IP
//   DEV_CHECK     optional   "0" = do not compare X-Device with the link's device
//   IP_FAMILY_STRICT optional "1" = also refuse when the link was made on IPv4 but is used on IPv6 (or the reverse)
//   DEFAULT_REF   optional   fallback Referer for the upstream (default https://netfilm.world/)
//   PROXY         optional   HTTP proxies for the upstream calls, several allowed (comma / space / new line separated), each as
//                            ip:port:user:pass   or   http://user:pass@ip:port   or   ip:port
//                            (not set = the DEFAULT_PROXIES list written in this file, below).
//                            A link always uses the SAME proxy (chosen from its token), so the signed video link and the video bytes
//                            come from one IP; if that proxy is dead / blocked (429, 403, 503) the next proxy is tried.
//   PROXY_MODE    optional   "off" (default) = no proxy | "always" = every upstream call goes through a proxy, the Worker's own IP is never used
//                            "fallback" = go direct, use the proxies only when direct gives 429 / 403 / 503 / error
//   PROXY_TRIES   optional   how many different proxies one call may try (default 3)
//
// A link is  /p?u=<video url>&t=<token>&r=<referer>   (made by api.py / protect.py)

import { connect } from "cloudflare:sockets";

const enc = new TextEncoder();
const UA = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36";
const DEV_RE = /^[A-Za-z0-9_-]{8,40}$/;
let keyP = null;

const b64u = (buf) => {
  let s = "";
  for (const x of new Uint8Array(buf)) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64 = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return atob(s);
};
const key = (env) =>
  (keyP ||= crypto.subtle.importKey("raw", enc.encode(env.LINK_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]));
const sig = async (env, payload, u) =>
  b64u(await crypto.subtle.sign("HMAC", await key(env), enc.encode(payload + "|" + u))).slice(0, 30);
// ---- the source url is hidden inside the link (e=): url XOR HMAC-SHA256 keystream, same as protect.enc()/dec() ----
let ekP = null;
const ekey = (env) =>
  (ekP ||= crypto.subtle.digest("SHA-256", enc.encode("jf-enc|" + env.LINK_SECRET))
    .then((d) => crypto.subtle.importKey("raw", d, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])));
async function keystream(env, nonce, n) {
  const k = await ekey(env), blocks = Math.ceil(n / 32), out = new Uint8Array(blocks * 32);
  for (let i = 0; i < blocks; i++) {
    const m = new Uint8Array(16); m.set(nonce); new DataView(m.buffer).setUint32(12, i);
    out.set(new Uint8Array(await crypto.subtle.sign("HMAC", k, m)), i * 32);
  }
  return out;
}
async function encU(env, u) {
  const b = enc.encode(u), nonce = crypto.getRandomValues(new Uint8Array(12)), ks = await keystream(env, nonce, b.length);
  const o = new Uint8Array(12 + b.length); o.set(nonce);
  for (let i = 0; i < b.length; i++) o[12 + i] = b[i] ^ ks[i];
  return b64u(o);
}
async function decU(env, e) {
  try {
    const raw = Uint8Array.from(unb64(e), (c) => c.charCodeAt(0)), nonce = raw.slice(0, 12), ct = raw.slice(12);
    const ks = await keystream(env, nonce, ct.length), o = new Uint8Array(ct.length);
    for (let i = 0; i < ct.length; i++) o[i] = ct[i] ^ ks[i];
    return new TextDecoder().decode(o);
  } catch { return ""; }
}
const devHash = async (dev) => b64u(await crypto.subtle.digest("SHA-256", enc.encode(dev))).slice(0, 12);

function same(a, b) {                       // constant-time string compare
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ---- same "person" key as guard.ip_key(): IPv4 as is, IPv6 grouped by /64 ----
function v6groups(ip) {
  ip = ip.split("%")[0].toLowerCase();
  const m = ip.match(/^(.*:)(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) ip = m[1] + ((+m[2] << 8) | +m[3]).toString(16) + ":" + ((+m[4] << 8) | +m[5]).toString(16);
  const parts = ip.split("::");
  if (parts.length > 2) return null;
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  let g;
  if (parts.length === 2) {
    const fill = 8 - left.length - right.length;
    if (fill < 0) return null;
    g = [...left, ...Array(fill).fill("0"), ...right];
  } else g = left;
  if (g.length !== 8) return null;
  const out = g.map((x) => parseInt(x || "0", 16));
  return out.some((n) => isNaN(n) || n < 0 || n > 65535) ? null : out;
}
function v6text(g) {                         // same text as Python's ipaddress (longest zero run, first on a tie)
  let bs = -1, bl = 0, cs = -1, cl = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) {
      if (cs < 0) { cs = i; cl = 1; } else cl++;
      if (cl > bl) { bs = cs; bl = cl; }
    } else { cs = -1; cl = 0; }
  }
  const hx = g.map((n) => n.toString(16));
  return bl > 1 ? hx.slice(0, bs).join(":") + "::" + hx.slice(bs + bl).join(":") : hx.join(":");
}
function ipKey(ip) {
  if (!ip) return "";
  if (ip.includes(":")) {
    const g = v6groups(ip);
    if (!g) return ip;
    return "v6:" + v6text([g[0], g[1], g[2], g[3], 0, 0, 0, 0]);
  }
  return ip;
}

// ---- only public http(s) hosts ----
function safeUrl(u) {
  try {
    const p = new URL(u);
    if (p.protocol !== "http:" && p.protocol !== "https:") return false;
    const h = p.hostname.toLowerCase();
    if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return false;
    if (/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.test(h)) {
      const [a, b] = h.split(".").map(Number);
      if (a === 10 || a === 127 || a === 0 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return false;
    }
    if (h.startsWith("[")) return false;     // raw IPv6 hosts: not needed for video
    return true;
  } catch { return false; }
}

const deny = (code, why, cors) => (console.log("deny", code, why),
  new Response("forbidden (" + why + ")", { status: code, headers: new Headers({ ...(cors || {}), "Cache-Control": "no-store" }) }));


// ================= upstream through an HTTP proxy (PROXY) =================
// A Worker cannot use a proxy with fetch(), so we speak to it over a raw TCP socket:
//   https target:  CONNECT host:443  ->  startTls  ->  plain HTTP/1.1 request on the tunnel
//   http  target:  request with the full URL sent to the proxy
// Only HTTP proxies (optionally with user:pass).  SOCKS and https:// proxies are not supported.
const DEFAULT_PROXIES = [                      // ip:port:user:pass   (env PROXY wins)
  "45.38.107.97:6014:pifpgtdg:2dnuiyauxt6y",   // the only one of the 10 that answered (the others: 402 Payment Required / 407)
];
const CRLF = new Uint8Array([13, 10]), CRLF2 = new Uint8Array([13, 10, 13, 10]);
const txt = (b) => new TextDecoder().decode(b);
function idx(buf, seq) {
  outer: for (let i = 0; i + seq.length <= buf.length; i++) {
    for (let j = 0; j < seq.length; j++) if (buf[i + j] !== seq[j]) continue outer;
    return i;
  }
  return -1;
}
class Rd {                                     // small buffered reader over a ReadableStream of bytes
  constructor(readable) { this.r = readable.getReader(); this.buf = new Uint8Array(0); this.eof = false; }
  async fill() {
    if (this.eof) return false;
    const { value, done } = await this.r.read();
    if (done) { this.eof = true; return false; }
    const n = new Uint8Array(this.buf.length + value.length); n.set(this.buf); n.set(value, this.buf.length); this.buf = n;
    return true;
  }
  async until(seq, max) {                      // bytes before `seq` (seq is consumed)
    for (;;) {
      const i = idx(this.buf, seq);
      if (i >= 0) { const o = this.buf.slice(0, i); this.buf = this.buf.slice(i + seq.length); return o; }
      if (this.buf.length > max) throw new Error("head too big");
      if (!(await this.fill())) throw new Error("eof");
    }
  }
  async take(n) {                              // up to n bytes, null at end of stream
    while (!this.buf.length) if (!(await this.fill())) return null;
    const o = this.buf.slice(0, n); this.buf = this.buf.slice(o.length); return o;
  }
}
function parseProxy(s, env) {
  s = String(s || "").trim();
  if (!s) return null;
  const f = s.split(":");
  if (!/^[a-z]+:\/\//i.test(s) && f.length === 4) s = "http://" + encodeURIComponent(f[2]) + ":" + encodeURIComponent(f[3]) + "@" + f[0] + ":" + f[1];   // ip:port:user:pass
  else if (!/^[a-z]+:\/\//i.test(s)) s = "http://" + s;
  try {
    const p = new URL(s);
    if (p.protocol !== "http:" || !p.hostname) return null;
    return { host: p.hostname, port: +p.port || 0,
      ports: String((env && env.PROXY_PORTS) || "8080,3128,80,8888,3129,8000").split(",").map((x) => +x.trim()).filter((x) => x > 0 && x < 65536),
      auth: p.username ? "Basic " + btoa(decodeURIComponent(p.username) + ":" + decodeURIComponent(p.password)) : "" };
  } catch { return null; }
}
function proxyList(env) {
  const raw = env.PROXY ? String(env.PROXY).split(/[\s,;]+/) : DEFAULT_PROXIES;
  return raw.map((x) => parseProxy(x, env)).filter(Boolean);
}
const hash32 = (str) => { let h = 2166136261; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; };
const tmo = (p, ms, what) => Promise.race([p, new Promise((_, no) => setTimeout(() => no(new Error(what + " timeout")), ms))]);
async function headOf(rd) {                    // -> {status, headers}
  const lines = txt(await rd.until(CRLF2, 65536)).split("\r\n");
  const m = /^HTTP\/1\.[01] (\d{3})/.exec(lines[0] || "");
  if (!m) throw new Error("bad response");
  const headers = new Headers();
  for (const l of lines.slice(1)) {
    const i = l.indexOf(":");
    if (i > 0) { try { headers.append(l.slice(0, i).trim(), l.slice(i + 1).trim()); } catch {} }
  }
  return { status: +m[1], headers };
}
function bodyOf(rd, head, close, method, raw) {
  const st = head.status;
  if (method === "HEAD" || st === 204 || st === 304 || (st >= 100 && st < 200)) { close(); return null; }
  const chunked = /chunked/i.test(head.headers.get("transfer-encoding") || "");
  const cl = head.headers.get("content-length");
  let left = cl !== null && /^\d+$/.test(cl) ? +cl : -1;
  if (!chunked && raw) {
    // plain body (Content-Length or until close; we sent Connection: close): hand the socket bytes straight to the client.
    // No JavaScript runs per chunk, so a long video does not use up the Worker's CPU-time limit.
    let lead = rd.buf;
    if (left >= 0 && lead.length > left) lead = lead.slice(0, left);
    const src = raw();
    rd.r.releaseLock();
    const t = typeof IdentityTransformStream !== "undefined" ? new IdentityTransformStream() : new TransformStream();
    (async () => {
      try {
        if (lead.length) { const w = t.writable.getWriter(); await w.write(lead); w.releaseLock(); }
        await src.pipeTo(t.writable);
      } catch { try { await t.writable.abort(); } catch {} }
      finally { close(); }
    })();
    return t.readable;
  }
  return new ReadableStream({
    async pull(c) {
      try {
        if (chunked) {
          const size = parseInt(txt(await rd.until(CRLF, 128)).split(";")[0].trim(), 16);
          if (!(size >= 0)) throw new Error("bad chunk");
          if (size === 0) { c.close(); close(); return; }
          let n = size;
          while (n > 0) { const ch = await rd.take(n); if (!ch) throw new Error("short chunk"); c.enqueue(ch); n -= ch.length; }
          await rd.until(CRLF, 8);
        } else if (left >= 0) {
          if (left === 0) { c.close(); close(); return; }
          const ch = await rd.take(Math.min(65536, left));
          if (!ch) throw new Error("short body");
          left -= ch.length; c.enqueue(ch);
          if (left === 0) { c.close(); close(); }
        } else {
          const ch = await rd.take(65536);
          if (!ch) { c.close(); close(); return; }
          c.enqueue(ch);
        }
      } catch (e) { close(); c.error(e); }
    },
    cancel() { close(); },
  });
}
let okPort = 0;                                 // the proxy port that worked last (only used when no port was given)
async function proxyFetch(px, url, init) {
  if (px.port) return proxyFetchOnce(px, url, init, 0);
  const list = okPort ? [okPort, ...px.ports.filter((x) => x !== okPort)] : px.ports;
  let last = new Error("no proxy port");
  for (const port of list) {
    try { const r = await proxyFetchOnce({ ...px, port }, url, init, 0); okPort = port; return r; }
    catch (e) { last = e; }
  }
  throw last;
}
async function proxyFetchOnce(px, url, init, hop) {
  init = init || {};
  const u = new URL(url), tls = u.protocol === "https:", port = +u.port || (tls ? 443 : 80), method = init.method || "GET";
  const hd = new Headers(init.headers || {});
  hd.set("Host", u.host); hd.set("Accept-Encoding", "identity"); hd.set("Connection", "close");
  let sock = connect({ hostname: px.host, port: px.port }, { secureTransport: tls ? "starttls" : "off" });
  const close = () => { try { sock.close(); } catch {} };
  try {
    let w = sock.writable.getWriter(), rd = new Rd(sock.readable), target;
    if (tls) {
      await tmo((async () => {
        await w.write(enc.encode("CONNECT " + u.hostname + ":" + port + " HTTP/1.1\r\nHost: " + u.hostname + ":" + port + "\r\n" +
          (px.auth ? "Proxy-Authorization: " + px.auth + "\r\n" : "") + "\r\n"));
        const h = await headOf(rd);
        if (h.status !== 200) throw new Error("proxy CONNECT " + h.status);
        if (rd.buf.length) throw new Error("proxy sent early data");
      })(), 10000, "proxy connect");
      w.releaseLock(); rd.r.releaseLock();
      sock = sock.startTls({ expectedServerHostname: u.hostname });
      w = sock.writable.getWriter(); rd = new Rd(sock.readable);
      target = u.pathname + u.search;
    } else {
      if (px.auth) hd.set("Proxy-Authorization", px.auth);
      target = u.href;
    }
    let req = method + " " + target + " HTTP/1.1\r\n";
    for (const [k, v] of hd) req += k + ": " + v + "\r\n";
    await w.write(enc.encode(req + "\r\n"));
    const head = await tmo(headOf(rd), 20000, "proxy response");
    if ([301, 302, 303, 307, 308].includes(head.status) && head.headers.get("location") && hop < 4 && init.redirect !== "manual") {
      close();
      return proxyFetchOnce(px, new URL(head.headers.get("location"), u).href, init, hop + 1);
    }
    const resp = new Response(bodyOf(rd, head, close, method, () => sock.readable), { status: head.status, headers: head.headers });
    Object.defineProperty(resp, "url", { value: u.href });
    Object.defineProperty(resp, "viaProxy", { value: true });
    return resp;
  } catch (e) { close(); throw e; }
}
// every call to the video side goes through here (no proxy / PROXY_MODE=off = plain fetch, nothing changes)
// key = the link's token: the same link always starts with the same proxy (one IP for the signed link and the video)
const bad = (r) => [429, 403, 503].includes(r.status);
async function upFetch(env, url, init, key) {
  const list = proxyList(env), mode = String(env.PROXY_MODE || "off").toLowerCase();
  if (!list.length || mode === "off") return fetch(url, init);
  const start = hash32(String(key || "")) % list.length, tries = Math.max(1, Math.min(list.length, +env.PROXY_TRIES || 3));
  let first = null;
  if (mode === "fallback") {
    try { first = await fetch(url, init); } catch {}
    if (first && !bad(first)) return first;
  }
  let last = null, err = null;
  for (let i = 0; i < tries; i++) {
    let r;
    try { r = await proxyFetch(list[(start + i) % list.length], url, init); } catch (e) { err = e; continue; }
    if (!bad(r)) { if (first) { try { await first.body?.cancel(); } catch {} } return r; }
    if (last) { try { await last.body?.cancel(); } catch {} }
    last = r;                                    // blocked through this proxy: try the next one
  }
  if (first) { try { await last?.body?.cancel(); } catch {} return first; }
  if (last) return last;
  throw err || new Error("no proxy worked");
}

// ---- WORKER_RESOLVE: the Worker asks MovieBox for the signed video link ITSELF (same IP for link and video) ----
const MB_API = "https://h5-api.aoneroom.com/wefeed-h5api-bff";
const MB_HDR = { "User-Agent": UA, "Accept": "application/json", "X-Request-Lang": "en", "X-Client-Info": '{"timezone":"Asia/Kolkata"}', "Accept-Language": "en-IN,en;q=0.9" };
let mbTok = { v: "", t: 0 };
const mbCache = new Map();
async function mbToken(env, force, key) {
  if (!force && mbTok.v && Date.now() - mbTok.t < 600000) return mbTok.v;
  try {
    const r = await upFetch(env, (env.MB_API || MB_API) + "/home?host=" + (env.MB_HOST || "moviebox.ph"), { headers: { ...MB_HDR, "Referer": "https://moviebox.ph/", "Origin": "https://moviebox.ph", "Content-Type": "application/json" } }, key);
    const j = JSON.parse(r.headers.get("x-user") || "{}");
    if (j.token) mbTok = { v: j.token, t: Date.now() };
  } catch {}
  return mbTok.v;
}
async function mbDownload(env, sp, dom, q, ref, tk, key) {      // -> bcdnw link of the wanted quality ("" if none)
  const r = await upFetch(env, dom + "/wefeed-h5api-bff/subject/download?" + q, { headers: { ...MB_HDR, "Referer": ref, ...(tk ? { "Authorization": "Bearer " + tk } : {}) } }, key);
  if (r.status !== 200) return "";
  const d = ((await r.json()) || {}).data || {};
  const dl = (d.downloads || []).filter((x) => x && typeof x.url === "string" && x.url).map((x) => ({ r: +x.resolution || 0, u: x.url }));
  if (!dl.length) return "";
  const ex = dl.find((x) => x.r === (+sp.r || 0));
  if (ex) return ex.u;
  // this quality has no download link: take the best one below it (else the lowest) so the video still plays
  const below = dl.filter((x) => x.r <= (+sp.r || 0)).sort((a, b) => b.r - a.r)[0];
  return (below || dl.sort((a, b) => a.r - b.r)[0]).u;
}
async function mbResolve(env, sp, key) {                     // -> upstream video url ("" on failure)
  const ck = JSON.stringify(sp), hit = mbCache.get(ck);
  if (hit && Date.now() - hit.t < 900000) return hit.u;
  const dom = String(sp.dom || "").replace(/\/+$/, "");
  if (!safeUrl(dom)) return "";
  const q = "subjectId=" + encodeURIComponent(sp.s) + "&se=" + (+sp.se || 0) + "&ep=" + (+sp.ep || 0) + "&detailPath=" + encodeURIComponent(sp.d);
  const ref = dom + "/spa/videoPlayPage/movies/" + sp.d + "?id=" + sp.s + "&type=/movie/detail&detailSe=" + (+sp.se || 0) + "&detailEp=" + (+sp.ep || 0) + "&lang=en";
  for (let a = 0; a < 2; a++) {
    const tk = await mbToken(env, a > 0, key);
    // The "streams" mp4 links are on the bcdnxw host, which answers 427 to Cloudflare IPs (= this Worker).  The download API gives the same
    // movie on bcdnw, which Cloudflare IPs can fetch.  Use it for mp4 qualities (DL_LINKS=0 turns this off); falls back to the play API below.
    if (sp.l !== "hls" && !sp.m && env.DL_LINKS !== "0") {
      try {
        const u = await mbDownload(env, sp, dom, q, ref, tk, key);
        if (u) { mbCache.set(ck, { u, t: Date.now() }); if (mbCache.size > 200) mbCache.delete(mbCache.keys().next().value); return u; }
      } catch {}
    }
    let r;
    try { r = await upFetch(env, dom + "/wefeed-h5api-bff/subject/play?" + q, { headers: { ...MB_HDR, "Referer": ref, ...(tk ? { "Authorization": "Bearer " + tk } : {}) } }, key); } catch { return ""; }
    if ((r.status === 401 || r.status === 403) && a === 0) continue;
    let d; try { d = ((await r.json()) || {}).data || {}; } catch { return ""; }
    let u = "";
    if (sp.l === "hls") { const x = (d.hls || [])[sp.n]; u = (x && (x.url || x)) || ""; }
    else {
      const st = d.streams || [];
      const x = st.find((s) => s.url && (+s.resolutions || 0) === sp.r && s.url.includes(".m3u8") === !!sp.m) || st[sp.n];
      u = (x && x.url) || "";
    }
    if (typeof u === "string" && u) { mbCache.set(ck, { u, t: Date.now() }); if (mbCache.size > 200) mbCache.delete(mbCache.keys().next().value); return u; }
    return "";
  }
  return "";
}

// DEBUG=1 only: what did the video server say, which colo are we in, and which ips does Cloudflare's resolver give for the video host
async function dbgInfo(req, up, u, bodies) {
  const o = ["colo=" + ((req.cf && req.cf.colo) || "-")];
  try { o.push("final=" + new URL(up.url || u).hostname + (up.redirected ? "(redirected)" : "")); } catch {}
  const hs = [];
  for (const k of ["server", "cf-ray", "cf-mitigated", "retry-after", "via", "x-cache", "location", "content-type"]) { const v = up.headers.get(k); if (v) hs.push(k + "=" + v); }
  o.push("hdr=[" + hs.join(";") + "]");
  try {
    const r = await fetch("https://cloudflare-dns.com/dns-query?name=" + new URL(u).hostname + "&type=A", { headers: { Accept: "application/dns-json" } });
    const j = await r.json();
    o.push("dns=" + ((j.Answer || []).map((a) => a.data).join(",") || "none"));
  } catch { o.push("dns=err"); }
  o.push("bodies=" + bodies.join(" ## "));
  return o.join(" | ");
}

// ---- /t?k=<LINK_SECRET>: open in a browser. Runs the whole chain (token -> play link -> video bytes) FROM THE WORKER and says which step fails ----
function pairsOf(o, out) {
  if (o && typeof o === "object") {
    if (o.subjectId && o.detailPath) out.push([String(o.subjectId), String(o.detailPath)]);
    for (const v of Object.values(o)) pairsOf(v, out);
  }
}
async function selfTest(req, env) {
  const out = [], say = (x) => out.push(x);
  const list = proxyList(env), api = env.MB_API || MB_API;
  say("colo=" + ((req.cf && req.cf.colo) || "-") + " proxies=" + list.length + " mode=" + (env.PROXY_MODE || "off") + (typeof IdentityTransformStream !== "undefined" ? " streams=native" : ""));
  const step = async (name, fn) => {
    const t0 = Date.now();
    try { say(name + ": " + (await fn()) + " (" + (Date.now() - t0) + "ms)"); return true; }
    catch (e) { say(name + ": FAIL " + String((e && e.message) || e).replace(/[^\x20-\x7e]/g, "").slice(0, 150) + " (" + (Date.now() - t0) + "ms)"); return false; }
  };
  let tok = "", dom = "", home = {}, vid = "", ref = "", psid = "", pdp = "";
  await step("1 home/token", async () => {
    const r = await upFetch(env, api + "/home?host=" + (env.MB_HOST || "moviebox.ph"), { headers: { ...MB_HDR, "Referer": "https://moviebox.ph/", "Origin": "https://moviebox.ph" } }, "t");
    try { tok = JSON.parse(r.headers.get("x-user") || "{}").token || ""; } catch {}
    try { home = JSON.parse(await r.text()); } catch {}
    return r.status + (r.viaProxy ? " +px" : " direct") + " token=" + (tok ? "yes" : "NO");
  });
  if (tok) {
    await step("2 domain", async () => {
      const r = await upFetch(env, api + "/media-player/get-domain", { headers: { ...MB_HDR, "Authorization": "Bearer " + tok } }, "t");
      const j = await r.json().catch(() => ({}));
      dom = (typeof j.data === "string" ? j.data : "").replace(/\/+$/, "") || "https://netfilm.world";
      return r.status + " " + dom;
    });
    const c = []; pairsOf(home, c);
    say("movies in home: " + c.length);
    for (const [sid, dp] of c.slice(0, 5)) {
      if (vid) break;
      await step("3 play " + dp.slice(0, 20), async () => {
        ref = dom + "/spa/videoPlayPage/movies/" + dp + "?id=" + sid + "&type=/movie/detail&detailSe=0&detailEp=0&lang=en";
        const r = await upFetch(env, dom + "/wefeed-h5api-bff/subject/play?subjectId=" + encodeURIComponent(sid) + "&se=0&ep=0&detailPath=" + encodeURIComponent(dp), { headers: { ...MB_HDR, "Referer": ref, "Authorization": "Bearer " + tok } }, "t");
        const d = (((await r.json().catch(() => ({}))) || {}).data) || {};
        const st = (d.streams || []).filter((x) => x && x.url), mp = st.filter((x) => !x.url.includes(".m3u8"));
        vid = ((mp[0] || st[0] || {}).url) || "";
        if (vid) { psid = sid; pdp = dp; }
        return r.status + " video=" + (vid ? new URL(vid).hostname : "none");
      });
    }
    if (vid) {
      await step("3b download link", async () => {
        const q = "subjectId=" + encodeURIComponent(psid) + "&se=0&ep=0&detailPath=" + encodeURIComponent(pdp);
        const r = await upFetch(env, dom + "/wefeed-h5api-bff/subject/download?" + q, { headers: { ...MB_HDR, "Referer": ref, "Authorization": "Bearer " + tok } }, "t");
        const dl = ((((await r.json().catch(() => ({}))) || {}).data || {}).downloads || []).filter((x) => x && x.url);
        if (!dl.length) return r.status + " no download link";
        const x = dl[0], v = await upFetch(env, x.url, { headers: { "User-Agent": UA, "Accept": "*/*", "Referer": dom + "/", "Origin": dom, "Range": "bytes=0-65535" }, redirect: "follow" }, "t");
        let n = 0;
        if (v.body) { const rd = v.body.getReader(); for (;;) { const { value, done } = await rd.read(); if (done) break; n += value.length; if (n >= 65536) { await rd.cancel(); break; } } }
        return r.status + " " + dl.map((y) => y.resolution + "p").join("/") + " | " + new URL(x.url).hostname + " -> " + v.status + " bytes=" + n;
      });
      await step("4 video 1MB (play link, bcdnxw: 427 here is normal)", async () => {
        const r = await upFetch(env, vid, { headers: { "User-Agent": UA, "Accept": "*/*", "Referer": dom + "/", "Origin": dom, "Range": "bytes=0-1048575" }, redirect: "follow" }, "t");
        let n = 0;
        if (r.body) { const rd = r.body.getReader(); for (;;) { const { value, done } = await rd.read(); if (done) break; n += value.length; if (n >= 1048576) { await rd.cancel(); break; } } }
        return r.status + " server=" + (r.headers.get("server") || "-") + (r.viaProxy ? " +px" : " direct") + " bytes=" + n;
      });
    }
  }
  return new Response(out.join("\n") + "\n", { status: 200, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const allow = (env.ALLOW_ORIGIN || "").split(",").map((s) => s.trim().replace(/\/+$/, "")).filter(Boolean);
    const origin = req.headers.get("Origin") || "";
    let ref = "";
    try { ref = new URL(req.headers.get("Referer") || "").origin; } catch {}

    // only your own site may use this Worker (a plain <video> sends no Origin, so Referer is checked then)
    if (allow.length && ((origin && !allow.includes(origin)) || (!origin && ref && !allow.includes(ref)))) return deny(403, "origin");

    const cors = {
      "Access-Control-Allow-Origin": origin || "*",
      "Vary": "Origin",
      "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges, X-Jf-Tries",
    };
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: { ...cors,
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Allow-Headers": "Range, X-Device, X-Captcha, Content-Type",
        "Access-Control-Max-Age": "86400" } });
    }
    if (url.pathname === "/t") {
      if (!env.LINK_SECRET || !same(url.searchParams.get("k") || "", env.LINK_SECRET)) return deny(403, "bad", cors);
      return selfTest(req, env);
    }
    if (url.pathname !== "/p") return new Response("not found", { status: 404 });
    if (req.method !== "GET" && req.method !== "HEAD") return deny(405, "method", cors);
    if (!env.LINK_SECRET) return deny(500, "no secret", cors);

    // ---- the wall: signature, expiry, IP, device ----
    let u = url.searchParams.get("u") || "";
    const eu = url.searchParams.get("e");
    if (eu) u = await decU(env, eu);
    const t = url.searchParams.get("t") || "";
    const dot = t.indexOf(".");
    if (!u || dot < 1) return deny(403, "bad", cors);
    const payload = t.slice(0, dot);
    if (!same(t.slice(dot + 1), await sig(env, payload, u))) return deny(403, "bad", cors);
    let p;
    try { p = JSON.parse(unb64(payload)); } catch { return deny(403, "bad", cors); }
    if (p.k !== "s") return deny(403, "kind", cors);
    if (Date.now() / 1000 > Number(p.e)) return deny(403, "expired", cors);

    if (env.IP_CHECK !== "0") {
      const mine = ipKey(req.headers.get("CF-Connecting-IP") || "");
      const was = String(p.i || "");
      const fam = (x) => (x.includes(":") ? 6 : 4);
      // the main server may have seen the visitor on IPv4 while Cloudflare sees IPv6 (or the reverse): that is not a different person
      const skip = env.IP_FAMILY_STRICT !== "1" && mine && was && fam(mine) !== fam(was);
      if (!skip && mine !== was) return deny(403, "ip", cors);
    }
    if (env.DEV_CHECK !== "0" && p.d) {
      const dev = req.headers.get("X-Device") || "";
      if (!DEV_RE.test(dev) || !same(await devHash(dev), String(p.d))) return deny(403, "device", cors);
    }
    if (u.startsWith("mb:")) {
      let sp; try { sp = JSON.parse(u.slice(3)); } catch { return deny(403, "bad", cors); }
      u = await mbResolve(env, sp, payload);
      if (!u) return deny(502, "resolve failed", cors);
    }
    if (!safeUrl(u)) return deny(403, "url", cors);

    // ---- fetch the video from upstream ----
    const qq = url.searchParams.get("q");        // referer, hidden the same way as the url (old links used plain r=)
    let r0 = (qq ? await decU(env, qq) : url.searchParams.get("r")) || env.DEFAULT_REF || "https://netfilm.world/";
    if (!safeUrl(r0)) r0 = env.DEFAULT_REF || "https://netfilm.world/";
    // The Python server (httpx) sends: UA, Accept, Referer, Origin, Accept-Encoding "gzip, deflate" and gets 206.
    // So try that EXACT set first, then a few variants (each try is noted as status:server in X-Jf-Tries).
    const rg = req.headers.get("Range");
    const mk = (o, r, ae) => {
      const hh = new Headers({ "User-Agent": UA, "Accept": "*/*" });
      if (ae) hh.set("Accept-Encoding", ae);
      if (r) hh.set("Referer", r0);
      if (o) hh.set("Origin", new URL(r0).origin);
      if (rg) hh.set("Range", rg);
      return hh;
    };
    const profiles = [[1, 1, "gzip, deflate"], [1, 1, null], [0, 1, "identity;q=1, *;q=0"], [0, 0, null]];
    let up = null;
    const tries = [], dbg = [];
    for (const [o, r, ae] of profiles) {
      try { up = await upFetch(env, u, { method: req.method, headers: mk(o, r, ae), redirect: "follow" }, payload); }
      catch (e) { tries.push("err:" + String((e && e.message) || e).replace(/[^\x20-\x7e]/g, "").slice(0, 60)); up = null; continue; }
      tries.push(up.status + ":" + (up.headers.get("server") || "-") + (up.headers.get("cf-ray") ? "+ray" : "") + (up.viaProxy ? "+px" : ""));
      if (up.status < 400 || up.status === 416) break;
      if (env.DEBUG === "1") { try { dbg.push((await up.clone().text()).slice(0, 70).replace(/\s+/g, " ")); } catch {} }
      if (up.status === 429) break;                 // rate-limited: more tries only make it worse
    }
    const tr = tries.join(",");
    if (!up) return deny(502, "upstream unreachable tries=" + tr, cors);
    if (up.status >= 400 && up.status !== 416) {
      let extra = "";
      if (env.DEBUG === "1") extra = " | " + await dbgInfo(req, up, u, dbg);      // Worker Settings -> Variables: DEBUG = 1
      return deny(502, "upstream " + up.status + " tries=" + tr + extra, cors);
    }

    const ct = (up.headers.get("content-type") || "").toLowerCase();
    if (ct.includes("mpegurl") || u.split("?")[0].endsWith(".m3u8")) {
      // playlist: every line gets a fresh signed link with the SAME session / IP / device claims
      const text = await up.text();
      const base = up.url || u;
      const fix = async (x) => {
        const abs = new URL(x.trim(), base).href;
        return "/p?e=" + (await encU(env, abs)) + "&t=" + payload + "." + (await sig(env, payload, abs)) + "&q=" + (await encU(env, r0));
      };
      const lines = await Promise.all(text.split(/\r?\n/).map(async (ln) => {
        if (ln.startsWith("#")) {
          for (const m of [...ln.matchAll(/URI="([^"]+)"/g)]) {
            const rep = 'URI="' + (await fix(m[1])) + '"';
            ln = ln.replace(m[0], () => rep);
          }
          return ln;
        }
        return ln.trim() ? fix(ln) : ln;
      }));
      return new Response(lines.join("\n"), { status: 200, headers: { ...cors, "Content-Type": "application/vnd.apple.mpegurl", "Cache-Control": "no-store" } });
    }

    // video bytes: streamed straight through (nothing kept in memory; a closed player closes upstream too)
    const out = new Headers(cors);
    for (const k of ["content-type", "content-length", "content-range", "accept-ranges"]) {
      const v = up.headers.get(k);
      if (v) out.set(k, v);
    }
    out.set("X-Jf-Tries", tr);
    out.set("Cache-Control", "private, max-age=600");
    return new Response(req.method === "HEAD" ? null : up.body, { status: up.status, headers: out });
  },
};
