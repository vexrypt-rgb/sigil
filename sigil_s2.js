/* SIGIL S2 wire format — must stay aligned with the S2 section of sigil.py.
 * Same primitives and keys as S1: AES-256-GCM, PBKDF2-HMAC-SHA256 circle keys,
 * ECDH P-256 + HKDF-SHA256. Needs WebCrypto (browser or Node >= 20),
 * SIGIL_CODEBOOK (codebook_v2.js) for compact parts and SIGIL_P256 (p256.js)
 * for S2K / S2E.
 */
(function (global) {
  const VERSION2 = "S2";
  const PROTOCOL1 = "SIGIL.v1"; // circle-key salt prefix, unchanged in S2
  const PROTOCOL2 = "SIGIL.v2";
  const ITERS = 210000;
  const Z = 0x01, J = 0x02, M = 0x04, S = 0x08, RESERVED = 0xf0;
  const MID_LEN = 6, MAX_PARTS = 16, MAX_SENDER = 32;
  const NONCE_LEN = 12, TAG_LEN = 16, EPH_LEN = 33;
  const te = new TextEncoder();
  const td = new TextDecoder("utf-8", { fatal: true });
  const subtle = () => global.crypto.subtle;

  function b64e(bytes) {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function b64d(text) {
    if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("S2 blob is not base64url");
    text = text.replace(/-/g, "+").replace(/_/g, "/");
    while (text.length % 4) text += "=";
    const bin = atob(text);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function concat(...arrs) {
    const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }
  function hex(bytes) { return [...bytes].map(b => b.toString(16).padStart(2, "0")).join(""); }
  function randomBytes(n) { return global.crypto.getRandomValues(new Uint8Array(n)); }

  function b64Room(chars) {
    if (chars <= 0) return 0;
    return Math.floor(chars / 4) * 3 + Math.max(0, (chars % 4) - 1);
  }

  function header(flags, index, total, mid) {
    if (flags & (RESERVED | M)) throw new Error("header flags must not carry reserved or M bits");
    if (total === 1) {
      if (index !== 1 || (mid && mid.length)) throw new Error("single-part S2 frame has no part field");
      return Uint8Array.of(flags);
    }
    if (!(total >= 2 && total <= MAX_PARTS && index >= 1 && index <= total) || mid.length !== MID_LEN) {
      throw new Error("bad S2 part field");
    }
    return concat(Uint8Array.of(flags | M, ((index - 1) << 4) | (total - 1)), mid);
  }

  function parseFrame(data, ephemeral) {
    if (!data.length) throw new Error("Empty S2 blob.");
    const flags = data[0];
    if (flags & RESERVED) throw new Error("S2 header sets reserved bits (newer format?).");
    let pos = 1, index = 1, total = 1, mid = new Uint8Array(0);
    if (flags & M) {
      if (data.length < 2 + MID_LEN) throw new Error("S2 blob truncated.");
      index = (data[1] >> 4) + 1; total = (data[1] & 0x0f) + 1;
      if (total < 2 || index > total) throw new Error("Bad S2 part field.");
      mid = data.slice(2, 2 + MID_LEN);
      pos = 2 + MID_LEN;
    }
    if ((flags & J) && index === total) throw new Error("S2 join flag set on the last part.");
    if ((flags & S) && index !== 1) throw new Error("S2 sender flag set on a part other than 1.");
    const hdr = data.slice(0, pos);
    let eph = new Uint8Array(0);
    if (ephemeral) { eph = data.slice(pos, pos + EPH_LEN); pos += EPH_LEN; }
    const nonce = data.slice(pos, pos + NONCE_LEN);
    const ct = data.slice(pos + NONCE_LEN);
    if (eph.length !== (ephemeral ? EPH_LEN : 0) || nonce.length !== NONCE_LEN || ct.length < TAG_LEN) {
      throw new Error("S2 blob truncated.");
    }
    return { flags, index, total, mid, header: hdr, eph, nonce, ct };
  }

  function context(kind, ...route) { return te.encode(`${PROTOCOL2}.${kind}.${route.join(".")}`); }

  function cb() {
    if (!global.SIGIL_CODEBOOK) throw new Error("codebook_v2.js not loaded");
    return global.SIGIL_CODEBOOK;
  }

  // Sealer policy (mirrors sigil._s2_body): codebook only if it shrinks the part
  // and expands back to the same text up to letter case.
  function body(text, compact) {
    const raw = te.encode(text);
    if (compact) {
      const packed = cb().maybeCompress(text);
      if (packed.used && cb().expandV2(packed.bytes).toLowerCase() === text.toLowerCase()) {
        return { bytes: packed.bytes, used: true };
      }
    }
    return { bytes: raw, used: false };
  }

  function senderField(sender) {
    if (!sender) return new Uint8Array(0);
    const raw = te.encode(sender);
    if (raw.length > MAX_SENDER) throw new Error(`Sender name is longer than ${MAX_SENDER} UTF-8 bytes.`);
    return concat(Uint8Array.of(raw.length), raw);
  }

  function payloadRoom(maxLine, prefixLen, multi, ephLen) {
    const hdr = multi ? 2 + MID_LEN : 1;
    return b64Room(maxLine - prefixLen) - hdr - (ephLen || 0) - NONCE_LEN - TAG_LEN;
  }

  // Same algorithm as sigil.s2_split, on code points.
  function split(text, compact, sender, maxLine, prefixLen, ephLen) {
    const sfield = senderField(sender).length;
    const single = payloadRoom(maxLine, prefixLen, false, ephLen);
    if (sfield + body(text, compact).bytes.length <= single) return [[text, false]];
    const room = payloadRoom(maxLine, prefixLen, true, ephLen);
    if (room - sfield < 8) throw new Error("max_line is too small for an S2 fragment.");
    const size = (cps) => body(cps.join(""), compact).bytes.length;
    const parts = [];
    let rest = Array.from(text);
    while (rest.length) {
      const budget = room - (parts.length ? 0 : sfield);
      const span = Math.min(rest.length, budget * 12);
      if (span === rest.length && size(rest) <= budget) { parts.push([rest.join(""), false]); break; }
      let lo = 1, hi = span, best = 0;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (size(rest.slice(0, mid)) <= budget) { best = mid; lo = mid + 1; } else hi = mid - 1;
      }
      if (!best) throw new Error("max_line is too small for an S2 fragment.");
      let cut = best, join = false;
      if (compact) {
        const floor = Math.max(1, best >> 1);
        const rfind = (end) => { for (let c = Math.min(end, rest.length - 1); c >= floor; c--) if (rest[c] === " ") return c; return -1; };
        let c = rfind(best);
        while (c >= floor && size(rest.slice(0, c)) > budget) c = rfind(c - 1);
        if (c >= floor && c + 1 < rest.length) { cut = c; join = true; }
      }
      parts.push([rest.slice(0, cut).join(""), join]);
      rest = rest.slice(cut + (join ? 1 : 0));
    }
    if (parts.length > MAX_PARTS) {
      throw new Error(`S2 carries at most ${MAX_PARTS} parts; this message needs ${parts.length}. Shorten it or use S1.`);
    }
    return parts;
  }

  function frames(text, compact, sender, maxLine, prefixLen, ephLen) {
    const parts = split(text, compact, sender, maxLine, prefixLen, ephLen);
    const total = parts.length;
    const mid = total > 1 ? randomBytes(MID_LEN) : new Uint8Array(0);
    return parts.map(([part, join], k) => {
      const b = body(part, compact);
      let flags = (b.used ? Z : 0) | (join ? J : 0);
      let sf = new Uint8Array(0);
      if (k === 0 && sender) { flags |= S; sf = senderField(sender); }
      return { header: header(flags, k + 1, total, mid), pt: concat(sf, b.bytes) };
    });
  }

  function unpack(flags, pt) {
    let sender = null;
    if (flags & S) {
      const n = pt.length ? pt[0] : 0;
      if (n < 1 || n > MAX_SENDER || pt.length < 1 + n) throw new Error("Bad S2 sender field.");
      sender = td.decode(pt.slice(1, 1 + n));
      pt = pt.slice(1 + n);
    }
    if (flags & Z) {
      if (!pt.length || pt[0] !== cb().MAGIC2) throw new Error("S2 codebook body does not start with the v2 magic byte.");
      return { sender, text: cb().expandV2(pt) };
    }
    return { sender, text: td.decode(pt) };
  }

  async function circleKey(name, passphrase) {
    const salt = new Uint8Array(await subtle().digest("SHA-256", te.encode(PROTOCOL1 + ".circle.salt." + name))).slice(0, 16);
    const base = await subtle().importKey("raw", te.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    return subtle().deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: ITERS }, base,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  // HKDF-SHA256 with no salt (RFC 5869: HashLen zero bytes), same as sigil.ecdh_key.
  async function ecdhKey(priv, pub, info) {
    const bits = await subtle().deriveBits({ name: "ECDH", public: pub }, priv, 256);
    const ikm = await subtle().importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    return subtle().deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info }, ikm,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  async function gcmSeal(key, nonce, pt, aad) {
    return new Uint8Array(await subtle().encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, pt));
  }
  async function gcmOpen(key, nonce, ct, aad) {
    return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, key, ct));
  }

  function slugify(name, n = 4) {
    const cleaned = name.toLowerCase().replace(/[^a-z0-9]/g, "") || "circ";
    return (cleaned + "x".repeat(n)).slice(0, n);
  }

  async function sealCircle(name, passphrase, text, opts = {}) {
    const { compact = false, sender = "", maxLine = 256 } = opts;
    const key = await circleKey(name, passphrase);
    const prefix = `${VERSION2}C.${slugify(name)}.`;
    const ctx = context("C", name);
    const lines = [];
    for (const f of frames(text, compact, sender, maxLine, prefix.length, 0)) {
      const nonce = randomBytes(NONCE_LEN);
      const ct = await gcmSeal(key, nonce, f.pt, concat(f.header, ctx));
      lines.push(prefix + b64e(concat(f.header, nonce, ct)));
    }
    return lines;
  }

  // local: {short, pk (b64 compressed), priv (ECDH CryptoKey)}; contact: {short, pk}
  async function sealDirected(local, contact, text, opts = {}) {
    const { ephemeral = false, compact = false, sender = "", maxLine = 256 } = opts;
    const P = global.SIGIL_P256;
    if (!P) throw new Error("p256.js not loaded");
    const theirPk = b64d(contact.pk);
    const theirPub = await P.importCompressed(theirPk);
    const lines = [];
    if (ephemeral) {
      const prefix = `${VERSION2}E.${contact.short}.`;
      const ctx = context("E", contact.short);
      for (const f of frames(text, compact, sender, maxLine, prefix.length, EPH_LEN)) {
        const eph = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
        const ephPk = P.compress(new Uint8Array(await subtle().exportKey("raw", eph.publicKey)));
        const key = await ecdhKey(eph.privateKey, theirPub, concat(ctx, ephPk, theirPk));
        const nonce = randomBytes(NONCE_LEN);
        const ct = await gcmSeal(key, nonce, f.pt, concat(f.header, ctx));
        lines.push(prefix + b64e(concat(f.header, ephPk, nonce, ct)));
      }
    } else {
      const prefix = `${VERSION2}K.${contact.short}.${local.short}.`;
      const ctx = context("K", local.short, contact.short);
      const key = await ecdhKey(local.priv, theirPub, concat(ctx, b64d(local.pk), theirPk));
      for (const f of frames(text, compact, sender, maxLine, prefix.length, 0)) {
        const nonce = randomBytes(NONCE_LEN);
        const ct = await gcmSeal(key, nonce, f.pt, concat(f.header, ctx));
        lines.push(prefix + b64e(concat(f.header, nonce, ct)));
      }
    }
    return lines;
  }

  function findTokens(text) {
    return text.replace(/,/g, " ").split(/\s+/).filter(t => /^S2[CKE]\./.test(t));
  }

  function parseToken(token) {
    const fields = token.split(".");
    const kind = fields[0].slice(2);
    if (fields[0].slice(0, 2) !== VERSION2 || !"CKE".includes(kind) || kind.length !== 1 || fields.length < 3) {
      throw new Error("Not a SIGIL S2 message.");
    }
    const route = fields.slice(1, -1);
    if ((kind === "K" && route.length !== 2) || (kind !== "K" && route.length !== 1)) throw new Error("Bad S2 route.");
    const frame = parseFrame(b64d(fields[fields.length - 1]), kind === "E");
    return { kind, route, frame };
  }

  function result(frame, extra, pt) {
    const { sender, text } = unpack(frame.flags, pt);
    return Object.assign({
      ok: true, version: 2, index: frame.index, total: frame.total, part: `${frame.index}/${frame.total}`,
      mid: hex(frame.mid), join: !!(frame.flags & J), codebook: !!(frame.flags & Z), sender, plaintext: text,
    }, extra);
  }

  // keyring: {circles: [{name, pass}], signets: [{name, short, pk, priv}], contacts: [{alias, short, pk}]}
  async function openToken(token, keyring) {
    const { kind, route, frame } = parseToken(token);
    const P = global.SIGIL_P256;
    if (kind === "C") {
      const slug = route[0];
      for (const c of keyring.circles || []) {
        if (slugify(c.name) !== slug && c.name.toLowerCase() !== slug) continue;
        const key = await circleKey(c.name, c.pass);
        let pt;
        try { pt = await gcmOpen(key, frame.nonce, frame.ct, concat(frame.header, context("C", c.name))); }
        catch (e) { continue; }
        return result(frame, { mode: "circle", circle: c.name }, pt);
      }
      throw new Error(`Could not open circle message for slug '${slug}'.`);
    }
    const toShort = route[0];
    const local = (keyring.signets || []).find(s => s.short === toShort);
    if (!local) throw new Error(`Addressed to signet ${toShort}, which is not on this device.`);
    const myPk = b64d(local.pk);
    if (kind === "K") {
      const fromShort = route[1];
      const contact = (keyring.contacts || []).find(c => c.short === fromShort);
      if (!contact) throw new Error(`Sender ${fromShort} is not in your contacts.`);
      const theirPk = b64d(contact.pk);
      const ctx = context("K", fromShort, toShort);
      const key = await ecdhKey(local.priv, await P.importCompressed(theirPk), concat(ctx, theirPk, myPk));
      const pt = await gcmOpen(key, frame.nonce, frame.ct, concat(frame.header, ctx));
      return result(frame, { mode: "signet", to: local.name, from: contact.alias || fromShort }, pt);
    }
    const ctx = context("E", toShort);
    const key = await ecdhKey(local.priv, await P.importCompressed(frame.eph), concat(ctx, frame.eph, myPk));
    const pt = await gcmOpen(key, frame.nonce, frame.ct, concat(frame.header, ctx));
    return result(frame, { mode: "ephemeral", to: local.name, from: "ephemeral-sender" }, pt);
  }

  // Exact S2 rejoin: text_i followed by one space when J is set. No heuristic.
  function stitch(parts) {
    return parts.map(p => p.plaintext + (p.join ? " " : "")).join("");
  }

  // Group opened parts by (mode, route, message id, n). Returns
  // [{complete, parts (ordered), text?, sender, missing}].
  function group(results) {
    const buckets = new Map();
    for (const r of results) {
      const k = [r.mode, r.circle || "", r.to || "", r.from || "", r.mid, r.total].join("\u0000");
      if (!buckets.has(k)) buckets.set(k, new Map());
      const b = buckets.get(k);
      if (!b.has(r.index)) b.set(r.index, r); // replayed duplicate ignored
    }
    const out = [];
    for (const b of buckets.values()) {
      const any = b.values().next().value;
      const parts = [...b.keys()].sort((x, y) => x - y).map(i => b.get(i));
      const missing = [];
      for (let i = 1; i <= any.total; i++) if (!b.has(i)) missing.push(i);
      const complete = missing.length === 0;
      out.push({ complete, parts, missing, text: complete ? stitch(parts) : null,
        sender: b.has(1) ? b.get(1).sender : null, mode: any.mode, circle: any.circle, to: any.to, from: any.from, total: any.total });
    }
    return out;
  }

  global.SIGIL_S2 = {
    VERSION2, PROTOCOL2, FLAGS: { Z, J, M, S }, MID_LEN, MAX_PARTS, MAX_SENDER,
    b64e, b64d, b64Room, header, parseFrame, context, payloadRoom, split, frames, unpack,
    circleKey, ecdhKey, sealCircle, sealDirected, findTokens, parseToken, openToken, stitch, group, slugify,
  };
})(typeof window !== "undefined" ? window : globalThis);
