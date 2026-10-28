// JaatFlix video Worker - carries the video bytes so the main server's data limit is not used.
//
// Settings (Worker -> Settings -> Variables and Secrets):
//   LINK_SECRET   (required, Secret)  the SAME value as LINK_SECRET on the main server
//   ALLOW_ORIGIN  (recommended)       your site, e.g. https://jaatflix.blitz.cloud  (comma separated for more)
//   IP_CHECK      optional   "0" = do not compare the visitor IP with the link's IP
//   DEV_CHECK     optional   "0" = do not compare X-Device with the link's device
//   IP_FAMILY_STRICT optional "1" = also refuse when the link was made on IPv4 but is used on IPv6 (or the reverse)
//   DEFAULT_REF   optional   fallback Referer for the upstream (default https://netfilm.world/)
//
// A link is  /p?u=<video url>&t=<token>&r=<referer>   (made by api.py / protect.py)

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
    const u = url.searchParams.get("u") || "";
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
    if (!safeUrl(u)) return deny(403, "url", cors);

    // ---- fetch the video from upstream ----
    let r0 = url.searchParams.get("r") || env.DEFAULT_REF || "https://netfilm.world/";
    if (!safeUrl(r0)) r0 = env.DEFAULT_REF || "https://netfilm.world/";
    // try with Referer+Origin, then Referer only, then no extra headers (some CDNs answer 502/403 to one of these)
    const rg = req.headers.get("Range");
    const mk = (withOrigin, withRef) => {
      const hh = new Headers({ "User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity" });
      if (withRef) hh.set("Referer", r0);
      if (withOrigin) hh.set("Origin", new URL(r0).origin);
      if (rg) hh.set("Range", rg);
      return hh;
    };
    let up = null;
    const tries = [];
    for (const [o, r] of [[true, true], [false, true], [false, false]]) {
      try { up = await fetch(u, { method: req.method, headers: mk(o, r), redirect: "follow" }); }
      catch (e) { tries.push("err"); up = null; continue; }
      tries.push(up.status);
      if (up.status < 400 || up.status === 416) break;
    }
    const tr = tries.join(",");
    if (!up) return deny(502, "upstream unreachable tries=" + tr, cors);
    if (up.status >= 400 && up.status !== 416) {
      let host = ""; try { host = new URL(u).hostname; } catch {}
      return deny(502, "upstream " + up.status + " host=" + host + " tries=" + tr, cors);
    }

    const ct = (up.headers.get("content-type") || "").toLowerCase();
    if (ct.includes("mpegurl") || u.split("?")[0].endsWith(".m3u8")) {
      // playlist: every line gets a fresh signed link with the SAME session / IP / device claims
      const text = await up.text();
      const base = up.url || u;
      const fix = async (x) => {
        const abs = new URL(x.trim(), base).href;
        return "/p?u=" + encodeURIComponent(abs) + "&t=" + payload + "." + (await sig(env, payload, abs)) + "&r=" + encodeURIComponent(r0);
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
