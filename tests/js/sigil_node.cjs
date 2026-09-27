#!/usr/bin/env node
/*
 * Node driver for the browser S2 code (sigil_s2.js + codebook_v2.js + p256.js).
 * Used by tests/test_js_interop.py; also runnable by hand:
 *
 *   node tests/js/sigil_node.cjs selftest
 *   node tests/js/sigil_node.cjs vectors tests/vectors/s2c.json
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
  return { name: s.name, short: s.short, pk: s.pk, priv };
}

async function keyring(job) {
  return {
    circles: job.circles || [],
    signets: await Promise.all((job.signets || []).map(importSignet)),
    contacts: job.contacts || [],
  };
}

async function openAll(lines, ring) {
  const results = [], errors = [];
  for (const line of lines) {
    for (const tok of S2.findTokens(line)) {
      try { results.push(await S2.openToken(tok, ring)); }
      catch (e) { errors.push(String(e && e.message || e)); }
    }
  }
  return { results, errors, messages: S2.group(results) };
}

async function runJob(job) {
  const ring = await keyring(job);
  if (job.op === "open") {
    const { results, errors, messages } = await openAll(job.lines, ring);
    return { parts: results, errors, messages };
  }
  if (job.op === "seal") {
    const out = [];
    for (const m of job.messages) {
      const opts = { compact: !!m.compact, sender: m.sender || "", maxLine: m.max_line || 256, ephemeral: !!m.ephemeral };
      if (m.mode === "C") out.push(await S2.sealCircle(m.circle.name, m.circle.pass, m.text, opts));
      else {
        const local = ring.signets.find(s => s.short === m.from_short);
        out.push(await S2.sealDirected(local, m.contact, m.text, opts));
      }
    }
    return { lines: out };
  }
  throw new Error("unknown op " + job.op);
}

async function vectors(file) {
  const v = JSON.parse(fs.readFileSync(file, "utf8"));
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
  console.log("js selftest ok (S2C raw/unicode/compact/sender, S2K, S2E)");
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
