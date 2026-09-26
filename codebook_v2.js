/* SIGIL codebook v2 — must stay aligned with codebook.py compress_v2 / expand_v2 */
(function (global) {
  const MAGIC2 = 0xC2;
  const PUNCT = " .,:\n-/?!'\"();+";

  class BitsOut {
    constructor() { this.buf = []; this.acc = 0n; this.n = 0; }
    write(value, width) {
      const v = BigInt(value) & ((1n << BigInt(width)) - 1n);
      this.acc = (this.acc << BigInt(width)) | v;
      this.n += width;
      while (this.n >= 8) {
        this.n -= 8;
        this.buf.push(Number((this.acc >> BigInt(this.n)) & 0xffn));
        this.acc &= (1n << BigInt(this.n)) - 1n;
      }
    }
    finish() {
      if (this.n) {
        this.buf.push(Number((this.acc << BigInt(8 - this.n)) & 0xffn));
        this.acc = 0n; this.n = 0;
      }
      return new Uint8Array(this.buf);
    }
  }

  class BitsIn {
    constructor(data) { this.data = data; this.i = 0; this.acc = 0n; this.n = 0; }
    read(width) {
      while (this.n < width) {
        if (this.i >= this.data.length) throw new Error("truncated bitstream");
        this.acc = (this.acc << 8n) | BigInt(this.data[this.i++]);
        this.n += 8;
      }
      this.n -= width;
      const v = Number((this.acc >> BigInt(this.n)) & ((1n << BigInt(width)) - 1n));
      this.acc &= (1n << BigInt(this.n)) - 1n;
      return v;
    }
  }

  function lexicon() {
    const w = global.SIGIL_LEXICON_V2;
    if (!w || w.length !== 4096) throw new Error("lexicon_v2.js missing");
    return w;
  }

  function indexMap() {
    const idx = new Map();
    lexicon().forEach((w, i) => idx.set(w, i));
    return idx;
  }

  function phrasesByLen() {
    const items = [];
    lexicon().forEach((w, i) => { if (w.indexOf(" ") >= 0) items.push([w, i]); });
    items.sort((a, b) => b[0].length - a[0].length);
    return items;
  }

  function compressV2(text) {
    const idx = indexMap();
    const phrases = phrasesByLen();
    const out = new BitsOut();
    const n = text.length;
    const lower = text.toLowerCase();
    let i = 0;

    function emitWord(index) {
      if (index < 64) { out.write(0, 3); out.write(index, 6); }
      else if (index < 320) { out.write(1, 3); out.write(index - 64, 8); }
      else { out.write(2, 3); out.write(index, 12); }
    }
    function emitInt(val) {
      if (val >= 0 && val <= 63) { out.write(3, 3); out.write(val, 6); }
      else {
        let zz = (val << 1) ^ (val >> 31);
        if (val < 0) {
          // JS >> 31 on negative is -1; use BigInt for correctness
          const big = BigInt(val);
          zz = Number((big << 1n) ^ (big >> 63n));
        }
        let bits = zz.toString(2).length;
        if (bits < 2) bits = 2;
        if (bits > 32) bits = 32;
        out.write(4, 3);
        out.write(bits - 1, 5);
        out.write(zz & ((1 << bits) - 1), bits);
      }
    }
    function emitPunct(ch) {
      out.write(5, 3);
      out.write(PUNCT.indexOf(ch), 4);
    }
    function emitRaw(s) {
      const bytes = new TextEncoder().encode(s);
      for (let k = 0; k < bytes.length; k += 16) {
        const chunk = bytes.subarray(k, k + 16);
        out.write(6, 3);
        out.write(chunk.length - 1, 4);
        for (const b of chunk) out.write(b, 8);
      }
    }

    while (i < n) {
      if (text[i] === "\n") { emitPunct("\n"); i++; continue; }
      if (/\s/.test(text[i])) { i++; continue; }

      let hit = null;
      const slice = lower.slice(i);
      for (const [phrase, index] of phrases) {
        if (slice.startsWith(phrase)) {
          const end = i + phrase.length;
          if (end < n && /[A-Za-z0-9]/.test(text[end])) continue;
          hit = [index, end];
          break;
        }
      }
      if (hit) { emitWord(hit[0]); i = hit[1]; continue; }

      const wm = text.slice(i).match(/^[A-Za-z][A-Za-z0-9']*/);
      if (wm) {
        const raw = wm[0];
        const k1 = raw.toLowerCase().replace(/_/g, " ");
        const k2 = raw.toLowerCase();
        if (idx.has(k1)) { emitWord(idx.get(k1)); i += raw.length; continue; }
        if (idx.has(k2)) { emitWord(idx.get(k2)); i += raw.length; continue; }
      }

      const nm = text.slice(i).match(/^-?\d+/);
      if (nm) { emitInt(parseInt(nm[0], 10)); i += nm[0].length; continue; }

      if (wm) { emitRaw(wm[0]); i += wm[0].length; continue; }

      const ch = text[i];
      if (PUNCT.indexOf(ch) >= 0) { emitPunct(ch); i++; continue; }
      emitRaw(ch); i++;
    }
    out.write(7, 3);
    const packed = out.finish();
    const all = new Uint8Array(1 + packed.length);
    all[0] = MAGIC2;
    all.set(packed, 1);
    return all;
  }

  function expandV2(data) {
    if (!data.length || data[0] !== MAGIC2) throw new Error("not codebook v2");
    const words = lexicon();
    const bits = new BitsIn(data.subarray(1));
    const parts = [];
    let needSpace = false;
    function pushToken(s) {
      if (needSpace && parts.length && !/[\s\n]$/.test(parts[parts.length - 1])) parts.push(" ");
      parts.push(s);
      needSpace = true;
    }
    for (;;) {
      const tag = bits.read(3);
      if (tag === 0) pushToken(words[bits.read(6)]);
      else if (tag === 1) pushToken(words[64 + bits.read(8)]);
      else if (tag === 2) pushToken(words[bits.read(12)]);
      else if (tag === 3) pushToken(String(bits.read(6)));
      else if (tag === 4) {
        const width = bits.read(5) + 1;
        const zz = bits.read(width);
        const val = (zz >>> 1) ^ -(zz & 1);
        pushToken(String(val));
      } else if (tag === 5) {
        const ch = PUNCT[bits.read(4)];
        if (".,:;?!".indexOf(ch) >= 0) { parts.push(ch); needSpace = true; }
        else if (ch === "\n") { parts.push("\n"); needSpace = false; }
        else { parts.push(ch); needSpace = false; }
      } else if (tag === 6) {
        const ln = bits.read(4) + 1;
        const raw = new Uint8Array(ln);
        for (let k = 0; k < ln; k++) raw[k] = bits.read(8);
        const s = new TextDecoder().decode(raw);
        if (/^[A-Za-z0-9]/.test(s)) pushToken(s);
        else { parts.push(s); needSpace = false; }
      } else if (tag === 7) break;
      else throw new Error("bad v2 tag " + tag);
    }
    return parts.join("");
  }

  function maybeCompress(text) {
    const packed = compressV2(text);
    const raw = new TextEncoder().encode(text);
    if (packed.length < raw.length) return { bytes: packed, used: true };
    return { bytes: raw, used: false };
  }

  function maybeExpand(bytes) {
    if (bytes.length && bytes[0] === MAGIC2) return expandV2(bytes);
    return new TextDecoder().decode(bytes);
  }

  global.SIGIL_CODEBOOK = { compressV2, expandV2, maybeCompress, maybeExpand, MAGIC2 };
})(typeof window !== "undefined" ? window : globalThis);
