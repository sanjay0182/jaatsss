// JaatFlix video Worker - carries the video bytes so the main server's data limit is not used.
//
// Settings (Worker -> Settings -> Variables and Secrets):
//   LINK_SECRET   (required, Secret)  the SAME value as LINK_SECRET on the main server
//   ALLOW_ORIGIN  (recommended)       your site, e.g. https://jaatflix.blitz.cloud  (comma separated for more)
//   IP_CHECK      optional   "0" = do not compare the visitor IP with the link's IP
//   DEV_CHECK     optional   "0" = do not compare X-Device with the link's device
//   IP_FAMILY_STRICT optional "1" = also refuse when the link was made on IPv4 but is used on IPv6 (or the reverse)
//   DEFAULT_REF   optional   fallback Referer for the upstream (default https://netfilm.world/)
//   PROXY         optional   HTTP proxy for the upstream calls:  host:port  or  http://user:pass@host:port
//                            (not set = the DEFAULT_PROXY written in this file, below).  No port given = the common
//                            proxy ports are tried (PROXY_PORTS, default 8080,3128,80,8888,3129,8000) and the first that works is kept.
//   PROXY_MODE    optional   "always" (default) = every upstream call goes through the proxy, the Worker's own IP is never used
//                            "fallback" = go direct, use the proxy only when direct gives 429 / 403 / 503 / error | "off" = no proxy
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
const DEFAULT_PROXY = "143.244.130.180";       // the proxy under test: "ip" or "ip:port" or "http://user:pass@ip:port"  (env PROXY wins)
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
function parseProxy(env) {
  let s = String(env.PROXY || DEFAULT_PROXY || "").trim();
  if (!s) return null;
  if (!/^[a-z]+:\/\//i.test(s)) s = "http://" + s;
  try {
    const p = new URL(s);
    if (p.protocol !== "http:" || !p.hostname) return null;
    return { host: p.hostname, port: +p.port || 0,
      ports: String(env.PROXY_PORTS || "8080,3128,80,8888,3129,8000").split(",").map((x) => +x.trim()).filter((x) => x > 0 && x < 65536),
      auth: p.username ? "Basic " + btoa(decodeURIComponent(p.username) + ":" + decodeURIComponent(p.password)) : "" };
  } catch { return null; }
}
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
function bodyOf(rd, head, close, method) {
  const st = head.status;
  if (method === "HEAD" || st === 204 || st === 304 || (st >= 100 && st < 200)) { close(); return null; }
  const chunked = /chunked/i.test(head.headers.get("transfer-encoding") || "");
  const cl = head.headers.get("content-length");
  let left = cl !== null && /^\d+$/.test(cl) ? +cl : -1;
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
    const resp = new Response(bodyOf(rd, head, close, method), { status: head.status, headers: head.headers });
    Object.defineProperty(resp, "url", { value: u.href });
    Object.defineProperty(resp, "viaProxy", { value: true });
    return resp;
  } catch (e) { close(); throw e; }
}
// every call to the video side goes through here (PROXY unset = plain fetch, nothing changes)
async function upFetch(env, url, init) {
  const px = parseProxy(env), mode = String(env.PROXY_MODE || "always").toLowerCase();
  if (!px || mode === "off") return fetch(url, init);
  if (mode === "always") return proxyFetch(px, url, init);
  let r = null;
  try { r = await fetch(url, init); } catch {}
  if (r && ![429, 403, 503].includes(r.status)) return r;
  try {
    const p = await proxyFetch(px, url, init);
    if (r) { try { await r.body?.cancel(); } catch {} }
    return p;
  } catch (e) {
    if (r) return r;                           // the proxy is down too: give back what direct said
    throw e;
  }
}

// ---- WORKER_RESOLVE: the Worker asks MovieBox for the signed video link ITSELF (same IP for link and video) ----
const MB_API = "https://h5-api.aoneroom.com/wefeed-h5api-bff";
const MB_HDR = { "User-Agent": UA, "Accept": "application/json", "X-Request-Lang": "en", "X-Client-Info": '{"timezone":"Asia/Kolkata"}', "Accept-Language": "en-IN,en;q=0.9" };
let mbTok = { v: "", t: 0 };
const mbCache = new Map();
async function mbToken(env, force) {
  if (!force && mbTok.v && Date.now() - mbTok.t < 600000) return mbTok.v;
  try {
    const r = await upFetch(env, (env.MB_API || MB_API) + "/home?host=" + (env.MB_HOST || "moviebox.ph"), { headers: { ...MB_HDR, "Referer": "https://moviebox.ph/", "Origin": "https://moviebox.ph", "Content-Type": "application/json" } });
    const j = JSON.parse(r.headers.get("x-user") || "{}");
    if (j.token) mbTok = { v: j.token, t: Date.now() };
  } catch {}
  return mbTok.v;
}
async function mbResolve(env, sp) {                     // -> upstream video url ("" on failure)
  const ck = JSON.stringify(sp), hit = mbCache.get(ck);
  if (hit && Date.now() - hit.t < 900000) return hit.u;
  const dom = String(sp.dom || "").replace(/\/+$/, "");
  if (!safeUrl(dom)) return "";
  const q = "subjectId=" + encodeURIComponent(sp.s) + "&se=" + (+sp.se || 0) + "&ep=" + (+sp.ep || 0) + "&detailPath=" + encodeURIComponent(sp.d);
  const ref = dom + "/spa/videoPlayPage/movies/" + sp.d + "?id=" + sp.s + "&type=/movie/detail&detailSe=" + (+sp.se || 0) + "&detailEp=" + (+sp.ep || 0) + "&lang=en";
  for (let a = 0; a < 2; a++) {
    const tk = await mbToken(env, a > 0);
    let r;
    try { r = await upFetch(env, dom + "/wefeed-h5api-bff/subject/play?" + q, { headers: { ...MB_HDR, "Referer": ref, ...(tk ? { "Authorization": "Bearer " + tk } : {}) } }); } catch { return ""; }
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
      u = await mbResolve(env, sp);
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
      try { up = await upFetch(env, u, { method: req.method, headers: mk(o, r, ae), redirect: "follow" }); }
      catch (e) { tries.push("err"); up = null; continue; }
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
