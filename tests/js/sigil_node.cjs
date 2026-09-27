#!/usr/bin/env node
/*
 * Node driver for the browser S2 code (sigil_s2.js + codebook_v2.js + p256.js).
 * Used by tests/test_js_interop.py; also runnable by hand:
 *
 *   node tests/js/sigil_node.cjs selftest
 *   node tests/js/sigil_node.cjs vectors tests/vectors/s2c.json   (also s2k.json, s2s.json)
 *   node tests/js/sigil_node.cjs job < job.json      # {"op": "seal"|"open", ...}
 *
 * Keys in jobs come from the calling test (generated on the fly); nothing here
 * reads a keyring.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..", "..");
globalThis.window = globalThis;
for (const f of ["lexicon_v2.js", "codebook_v2.js", "p256.js", "sigil_s2.js"]) {
  vm.runInThisContext(fs.readFileSync(path.join(ROOT, f), "utf8"), { filename: f });
}
const S2 = globalThis.SIGIL_S2;

async function importSignet(s) {
  const priv = await crypto.subtle.importKey("jwk", s.jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const out = { name: s.name, short: s.short, pk: s.pk, priv };
  if (s.sign_jwk) {
    out.spk = s.sign_jwk.x;
    out.sign = await crypto.subtle.importKey("jwk", s.sign_jwk, { name: "Ed25519" }, false, ["sign"]);
  }
  return out;
}

async function keyring(job) {
  const signets = await Promise.all((job.signets || []).map(importSignet));
  const contacts = job.contacts || [];
  const keys = [...(job.signing_keys || [])];
  for (const c of contacts) if (c.spk) keys.push({ name: c.alias, spk: c.spk });
  for (const s of signets) if (s.spk) keys.push({ name: s.name, spk: s.spk });
  return { circles: job.circles || [], signets, contacts, keys };
}

async function openAll(lines, ring) {
  const results = [], errors = [];
  for (const line of lines) {
    for (const tok of S2.findTokens(line)) {
      try { results.push(await S2.openToken(tok, ring)); }
      catch (e) { errors.push(String(e && e.message || e)); }
    }
  }
  const messages = await S2.verifySigned(S2.group(results), ring.keys || []);
  return { results, errors, messages };
}

// Drop byte arrays (header/payload/ctx/keyid/sig) before printing JSON.
function plain(x) {
  return JSON.parse(JSON.stringify(x, (k, v) => (v instanceof Uint8Array ? undefined : v)));
}

async function runJob(job) {
  const ring = await keyring(job);
  if (job.op === "open") {
    const { results, errors, messages } = await openAll(job.lines, ring);
    return plain({ parts: results, errors, messages });
  }
  if (job.op === "seal") {
    const out = [];
    for (const m of job.messages) {
      const opts = { compact: !!m.compact, sender: m.sender || "", maxLine: m.max_line || 256, ephemeral: !!m.ephemeral };
      if (m.mode === "C") out.push(await S2.sealCircle(m.circle.name, m.circle.pass, m.text, opts));
      else if (m.mode === "S") {
        const signer = ring.signets.find(s => s.short === m.from_short);
        out.push(await S2.sealCircleSigned(m.circle.name, m.circle.pass, m.text, signer, opts));
      }
      else {
        const local = ring.signets.find(s => s.short === m.from_short);
        out.push(await S2.sealDirected(local, m.contact, m.text, opts));
      }
    }
    return { lines: out };
  }
  throw new Error("unknown op " + job.op);
}

const hexOf = (u) => Buffer.from(u).toString("hex");
const fromHex = (h) => new Uint8Array(Buffer.from(h, "hex"));

async function s2kVectors(v, file) {
  const byId = Object.fromEntries(await Promise.all(v.signets.map(async s => [s.id, Object.assign(await importSignet(s), { raw: s })])));
  const ringFor = (op) => ({ circles: [], signets: op.own.map(id => byId[id]),
    contacts: op.contacts.map(id => ({ alias: byId[id].name, short: byId[id].short, pk: byId[id].pk })), keys: [] });
  let pass = 0, fail = 0;
  const bad = (id, why) => { fail++; console.log(`FAIL ${id}: ${why}`); };
  for (const vec of v.positive) {
    const { results, errors, messages } = await openAll(vec.lines, ringFor(vec.opener));
    if (errors.length || results.length !== vec.parts.length) { bad(vec.id, errors.join("; ") || "part count"); continue; }
    let ok = results.every((r, k) => r.plaintext === vec.parts[k].plaintext && (r.sender || null) === (vec.parts[k].sender || null)
      && r.from === byId[vec.from].name && r.mode === "signet");
    if (!(messages.length === 1 && messages[0].complete && messages[0].text === vec.joined)) ok = false;
    // Byte-identical re-seal from the recorded nonce.
    const a = byId[vec.from], b = byId[vec.to];
    const ctx = S2.context("K", a.short, b.short);
    const key = await S2.ecdhKey(a.priv, await SIGIL_P256.importCompressed(S2.b64d(b.pk)), new Uint8Array([...ctx, ...S2.b64d(a.pk), ...S2.b64d(b.pk)]));
    for (const p of vec.parts) {
      const header = fromHex(p.header_hex), nonce = fromHex(p.nonce_hex);
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: new Uint8Array([...header, ...ctx]), tagLength: 128 }, key, fromHex(p.payload_hex)));
      if (`S2K.${b.short}.${a.short}.${S2.b64e(new Uint8Array([...header, ...nonce, ...ct]))}` !== p.token) ok = false;
    }
    if (ok) pass++; else bad(vec.id, "mismatch");
  }
  for (const vec of v.negative) {
    const { results } = await openAll([vec.line], ringFor(vec.opener));
    if (results.length) bad(vec.id, "opened but must fail"); else pass++;
  }
  console.log(`vectors ${path.basename(file)}: ${pass} ok, ${fail} failed`);
  return fail === 0;
}

async function s2sVectors(v, file) {
  const circles = Object.fromEntries(v.circles.map(c => [c.id, { name: c.name, pass: c.passphrase, key_hex: c.key_hex, slug: c.slug }]));
  const signets = Object.fromEntries(v.signets.map(s => [s.id, s]));
  const ringFor = (keys) => ({ circles: [circles.main], signets: [], contacts: [],
    keys: keys.map(id => ({ name: signets[id].name, spk: signets[id].sign_pk })) });
  let pass = 0, fail = 0;
  const bad = (id, why) => { fail++; console.log(`FAIL ${id}: ${why}`); };
  const kind = (m) => !m.complete ? "incomplete" : m.verified ? "" : (m.error.startsWith("BAD SIGNATURE") ? "bad-signature" : "unknown-signer");
  for (const vec of v.positive) {
    const { results, errors, messages } = await openAll(vec.lines, ringFor(vec.verifier_keys));
    if (errors.length || results.length !== vec.parts.length) { bad(vec.id, errors.join("; ") || "part count"); continue; }
    let ok = messages.length === 1 && messages[0].verified && messages[0].signer === vec.expect.signer
      && messages[0].text === vec.joined && messages[0].signerFp === signets[vec.signer].sign_fingerprint;
    results.forEach((r, k) => { if (r.plaintext !== vec.parts[k].plaintext || hexOf(r.payload) !== vec.parts[k].payload_hex) ok = false; });
    // Signed bytes, deterministic Ed25519 signature, byte-identical re-seal.
    const c = circles[vec.circle];
    const ctx = S2.context("S", c.name);
    const parts = vec.parts.map(p => ({ header: fromHex(p.header_hex), pt: fromHex(p.payload_hex) }));
    const tbs = S2.signedBytes(ctx, fromHex(vec.keyid_hex), parts);
    if (hexOf(tbs) !== vec.signed_bytes_hex) ok = false;
    const sk = await crypto.subtle.importKey("jwk", signets[vec.signer].sign_jwk, { name: "Ed25519" }, false, ["sign"]);
    if (hexOf(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, sk, tbs))) !== vec.sig_hex) ok = false;
    if (hexOf(await S2.keyId(S2.b64d(signets[vec.signer].sign_pk))) !== vec.keyid_hex) ok = false;
    const key = await crypto.subtle.importKey("raw", fromHex(c.key_hex), "AES-GCM", false, ["encrypt"]);
    for (const p of vec.parts) {
      const header = fromHex(p.header_hex), nonce = fromHex(p.nonce_hex);
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: new Uint8Array([...header, ...ctx]), tagLength: 128 }, key, fromHex(p.sealed_plaintext_hex)));
      if (`S2S.${c.slug}.${S2.b64e(new Uint8Array([...header, ...nonce, ...ct]))}` !== p.token) ok = false;
    }
    if (ok) pass++; else bad(vec.id, "mismatch");
  }
  for (const vec of v.messages) {
    const { messages } = await openAll(vec.lines, ringFor(vec.verifier_keys));
    const verified = messages.filter(m => m.verified);
    let ok;
    if (vec.expect.verified) ok = verified.length === 1 && verified[0].signer === vec.expect.signer;
    else ok = verified.length === 0 && messages.every(m => m.text === null)
      && (messages.length ? messages.map(kind) : ["incomplete"]).includes(vec.expect.error);
    if (ok) pass++; else bad(vec.id, JSON.stringify(messages.map(m => [m.verified, m.error, kind(m)])));
  }
  for (const vec of v.negative) {
    const { results } = await openAll([vec.line], ringFor(["alice", "bob"]));
    if (results.length) bad(vec.id, "opened but must fail"); else pass++;
  }
  console.log(`vectors ${path.basename(file)}: ${pass} ok, ${fail} failed`);
  return fail === 0;
}

async function vectors(file) {
  const v = JSON.parse(fs.readFileSync(file, "utf8"));
  if (v.suite.startsWith("S2K")) return s2kVectors(v, file);
  if (v.suite.startsWith("S2S")) return s2sVectors(v, file);
  const circles = Object.fromEntries(v.circles.map(c => [c.id, { name: c.name, pass: c.passphrase }]));
  let pass = 0, fail = 0;
  const bad = (id, why) => { fail++; console.log(`FAIL ${id}: ${why}`); };
  for (const vec of v.positive) {
    const ring = { circles: vec.keyring.map(id => circles[id]), signets: [], contacts: [] };
    const { results, errors, messages } = await openAll(vec.lines, ring);
    if (errors.length || results.length !== vec.parts.length) { bad(vec.id, errors.join("; ") || "part count"); continue; }
    let ok = true;
    results.forEach((r, k) => {
      const p = vec.parts[k];
      if (r.plaintext !== p.plaintext || r.join !== p.join || r.codebook !== p.codebook ||
          r.index !== p.index || r.total !== p.total || (r.sender || null) !== (p.sender || null)) ok = false;
    });
    const msg = messages.length === 1 && messages[0].complete ? messages[0].text : null;
    if (msg !== vec.joined) ok = false;
    if (ok) pass++; else bad(vec.id, "mismatch");
  }
  for (const vec of v.negative) {
    const ring = { circles: vec.keyring.map(id => circles[id]), signets: [], contacts: [] };
    const { results } = await openAll([vec.line], ring);
    if (results.length) bad(vec.id, "opened but must fail"); else pass++;
  }
  for (const vec of v.messages || []) {
    const ring = { circles: vec.keyring.map(id => circles[id]), signets: [], contacts: [] };
    const { messages } = await openAll(vec.lines, ring);
    const complete = messages.filter(m => m.complete).map(m => m.text).sort();
    if (JSON.stringify(complete) === JSON.stringify([...vec.complete].sort())) pass++;
    else bad(vec.id, `complete messages ${JSON.stringify(complete)}`);
  }
  console.log(`vectors ${path.basename(file)}: ${pass} ok, ${fail} failed`);
  return fail === 0;
}

async function selftest() {
  const name = "js-selftest-circle", pass = "public-js-selftest-DO-NOT-USE";
  const ring = { circles: [{ name, pass }], signets: [], contacts: [] };
  const cases = [
    ["portal at 1847 12 -320", {}],
    ["", {}],
    ["abcdefghij".repeat(40), {}],
    ["Grüße 🧭 北 שלום e\u0301 ".repeat(20).trim(), {}],
    ["nether roof stash at 0 128 0", { compact: true, sender: "Steve" }],
    [Array(40).fill("stash/portal/diamond/nether/roof").join("/"), { compact: true }],  // mid-word cuts
  ];
  for (const [text, opts] of cases) {
    const lines = await S2.sealCircle(name, pass, text, opts);
    if (lines.some(l => l.length > 256)) throw new Error("line too long");
    const { messages, errors } = await openAll(lines, ring);
    const got = messages[0] && messages[0].complete ? messages[0].text : (messages[0] && messages[0].parts[0].plaintext);
    if (errors.length || got !== text) throw new Error(`round-trip mismatch (${lines.length} lines): ${JSON.stringify(got)}`);
  }
  // Directed S2K / S2E between two throwaway WebCrypto keys.
  const mk = async (nm) => {
    const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const pk = S2.b64e(SIGIL_P256.compress(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey))));
    const short = S2.b64e(new Uint8Array(await crypto.subtle.digest("SHA-256", S2.b64d(pk)))).slice(0, 4).toLowerCase();
    return { name: nm, short, pk, priv: kp.privateKey };
  };
  const steve = await mk("Steve"), alex = await mk("Alex");
  const dring = { circles: [], signets: [alex], contacts: [{ alias: "Steve", short: steve.short, pk: steve.pk }] };
  for (const ephemeral of [false, true]) {
    const text = "don't sell the elytra ".repeat(15).trim();
    const lines = await S2.sealDirected(steve, { short: alex.short, pk: alex.pk }, text, { ephemeral, compact: true });
    const { messages, errors } = await openAll(lines, dring);
    if (errors.length || !messages[0].complete || messages[0].text !== text) throw new Error("directed mismatch " + errors);
  }
  // S2S: signed circle message; an unknown or tampered signer is never shown.
  const skp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const signer = { spk: S2.b64e(new Uint8Array(await crypto.subtle.exportKey("raw", skp.publicKey))), sign: skp.privateKey };
  const mkp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const mallory = { spk: S2.b64e(new Uint8Array(await crypto.subtle.exportKey("raw", mkp.publicKey))), sign: mkp.privateKey };
  const sring = { circles: [{ name, pass }], signets: [], contacts: [], keys: [{ name: "Steve", spk: signer.spk }] };
  for (const text of ["portal at 1847 12 -320", "abcdefghij ".repeat(40).trim(), ""]) {
    const lines = await S2.sealCircleSigned(name, pass, text, signer, { compact: true, sender: "Steve" });
    if (lines.some(l => l.length > 256 || !l.startsWith("S2S."))) throw new Error("bad S2S line");
    const { messages, errors } = await openAll(lines, sring);
    if (errors.length || messages.length !== 1 || !messages[0].verified || messages[0].signer !== "Steve"
        || messages[0].text.toLowerCase() !== text.toLowerCase()) throw new Error("S2S mismatch " + JSON.stringify(plain(messages)));
  }
  const forged = await openAll(await S2.sealCircleSigned(name, pass, "I am Steve", mallory, { sender: "Steve" }), sring);
  if (forged.messages[0].verified || forged.messages[0].text !== null) throw new Error("forged S2S accepted");
  console.log("js selftest ok (S2C raw/unicode/compact/sender, S2K, S2E, S2S)");
}

(async () => {
  const [cmd, arg] = process.argv.slice(2);
  if (cmd === "selftest") return selftest();
  if (cmd === "vectors") { if (!(await vectors(arg))) process.exitCode = 1; return; }
  if (cmd === "job") {
    const job = JSON.parse(fs.readFileSync(0, "utf8"));
    process.stdout.write(JSON.stringify(await runJob(job)));
    return;
  }
  console.error("usage: sigil_node.cjs selftest | vectors FILE | job < job.json");
  process.exitCode = 2;
})().catch(e => { console.error(e && e.stack || e); process.exitCode = 1; });
