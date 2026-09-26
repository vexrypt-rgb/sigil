/* secp256r1 decompress for SIGIL S1+PK / S1E / S1K wire format */
(function (global) {
  const P = BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
  const A = P - 3n;
  const B = BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

  function mod(n) { n %= P; return n < 0n ? n + P : n; }
  function pow(b, e) {
    let r = 1n; b = mod(b);
    while (e > 0n) {
      if (e & 1n) r = mod(r * b);
      b = mod(b * b);
      e >>= 1n;
    }
    return r;
  }
  function to32(n) {
    let h = mod(n).toString(16).padStart(64, "0");
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    return out;
  }
  function fromBytes(b) {
    let s = "0x";
    for (const x of b) s += x.toString(16).padStart(2, "0");
    return BigInt(s);
  }

  function decompress(comp) {
    if (!(comp instanceof Uint8Array) || comp.length !== 33) throw new Error("need 33-byte compressed point");
    if (comp[0] !== 2 && comp[0] !== 3) throw new Error("bad point prefix");
    const x = fromBytes(comp.subarray(1));
    const y2 = mod(mod(mod(x * x) * x) + mod(A * x) + B);
    // p ≡ 3 (mod 4) → sqrt = y2^((p+1)/4)
    let y = pow(y2, (P + 1n) / 4n);
    if (mod(y * y) !== y2) throw new Error("not on curve");
    const odd = (y & 1n) === 1n;
    if (odd !== (comp[0] === 3)) y = mod(P - y);
    const raw = new Uint8Array(65);
    raw[0] = 4;
    raw.set(to32(x), 1);
    raw.set(to32(y), 33);
    return raw;
  }

  function compress(raw) {
    if (raw.length === 33) return raw;
    if (raw.length !== 65 || raw[0] !== 4) throw new Error("need uncompressed P-256");
    const y = fromBytes(raw.subarray(33));
    const out = new Uint8Array(33);
    out[0] = (y & 1n) === 1n ? 3 : 2;
    out.set(raw.subarray(1, 33), 1);
    return out;
  }

  async function importUncompressed(raw65) {
    return crypto.subtle.importKey("raw", raw65, { name: "ECDH", namedCurve: "P-256" }, true, []);
  }
  async function importCompressed(comp33) {
    return importUncompressed(decompress(comp33));
  }

  global.SIGIL_P256 = { decompress, compress, importCompressed, importUncompressed };
})(typeof window !== "undefined" ? window : globalThis);
