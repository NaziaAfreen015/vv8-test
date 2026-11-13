/*
 * On-device browser AI as a fingerprinting surface — proof of concept.
 *
 * Probes Chrome's built-in AI APIs (Prompt API / LanguageModel, Summarizer,
 * Writer, Rewriter, Proofreader, Translator, LanguageDetector).
 *
 *  - Passive probes (run on load, no permission prompt, no user gesture):
 *      API presence + API surface, availability() over an option grid,
 *      availability() call timing, LanguageModel.params().
 *  - Active probes (only when the model is already "available", so they never
 *    trigger a download): session properties, tokenizer counts, inference
 *    timing (TTFT, decode rate), output determinism/hashes, language-detector
 *    confidences, summarizer/translator outputs.
 *
 * Add ?active=0 to the URL to skip active probes on load.
 */
(() => {
  "use strict";

  // ---------------------------------------------------------------- config
  const API_NAMES = [
    "LanguageModel",
    "Summarizer",
    "Writer",
    "Rewriter",
    "Proofreader",
    "Translator",
    "LanguageDetector",
  ];

  const LM_LANGS = ["en", "es", "ja", "de", "fr", "bn"];
  const TRANSLATOR_LANGS = [
    "es", "fr", "de", "it", "pt", "nl", "pl", "ru", "tr", "ar",
    "hi", "bn", "ja", "ko", "zh", "zh-Hant", "vi",
  ];

  const TOKEN_PROBES = {
    ascii: "The quick brown fox jumps over the lazy dog.",
    unicode: "naïve café 🤖 日本語のテキスト বাংলা লেখা",
    code: "function f(x) { return x * 2 + 1; } // comment",
    numbers: "3.14159265358979 2718281828 0xDEADBEEF",
  };

  const DETECT_PROBES = [
    "Hello, how are you doing today?",
    "Bonjour tout le monde",
    "Ich bin ein Berliner",
    "আমি বাংলায় গান গাই",
    "ok",
    "si",
  ];

  const SHORT_PROMPT =
    "Answer with a single lowercase word and no punctuation: what colour is a clear daytime sky?";
  const LONG_PROMPT =
    "List the numbers from 1 to 40 separated by single spaces. Output nothing else.";
  const SUMMARY_TEXT =
    "Browser fingerprinting identifies users by combining many small, individually " +
    "harmless attributes of their device and software, such as screen size, installed " +
    "fonts, and graphics hardware. Because no data is stored on the device, users " +
    "cannot easily clear or block it. New browser features can unintentionally add " +
    "attributes that make devices easier to tell apart.";
  const TRANSLATE_TEXT = "The weather is nice today, so we are going for a walk.";

  const SHORT_RUNS = 3;
  const TIMING_REPEATS = 5;
  const T = { availability: 10000, create: 60000, inference: 90000, misc: 5000 };

  // --------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const nowMs = () => performance.now();
  const round = (x, d = 2) => (x == null ? x : Math.round(x * 10 ** d) / 10 ** d);
  const errName = (e) => (e && e.name) || "Error";
  const errStr = (e) => (e instanceof Error ? `${e.name}: ${e.message}` : String(e));

  function withTimeout(promise, ms, label) {
    let timer;
    return Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms} ms`)), ms);
      }),
    ]).finally(() => clearTimeout(timer));
  }

  async function timed(label, fn, timeoutMs) {
    const t0 = nowMs();
    try {
      const value = await withTimeout(Promise.resolve().then(fn), timeoutMs, label);
      return { ok: true, value, ms: round(nowMs() - t0) };
    } catch (e) {
      return { ok: false, error: errStr(e), errorName: errName(e), ms: round(nowMs() - t0) };
    }
  }

  // WebIDL objects don't JSON.stringify their attributes, so copy them out.
  function pickProps(obj, keys) {
    if (!obj) return null;
    const out = {};
    for (const k of keys) {
      try {
        const v = obj[k];
        if (v !== undefined && typeof v !== "function") out[k] = v;
      } catch {
        /* ignore */
      }
    }
    return out;
  }

  function stats(xs) {
    if (!xs.length) return null;
    const s = [...xs].sort((a, b) => a - b);
    const mean = s.reduce((a, b) => a + b, 0) / s.length;
    const sd = Math.sqrt(s.reduce((a, b) => a + (b - mean) ** 2, 0) / s.length);
    return {
      n: s.length,
      min: round(s[0]),
      median: round(s[Math.floor(s.length / 2)]),
      mean: round(mean),
      max: round(s[s.length - 1]),
      sd: round(sd),
      raw: s.map((x) => round(x)),
    };
  }

  async function sha256Hex(str) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  // Stable JSON (sorted keys) so the hash doesn't depend on insertion order.
  function stableStringify(v) {
    if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
    if (v && typeof v === "object") {
      return `{${Object.keys(v)
        .sort()
        .map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`)
        .join(",")}}`;
    }
    return JSON.stringify(v === undefined ? null : v);
  }

  const present = (name) => typeof self[name] === "function" || (self[name] && typeof self[name] === "object");

  function setStatus(msg) {
    $("status").textContent = msg;
    console.log(`[local_model] ${msg}`);
  }

  // ---------------------------------------------------------------- report
  const report = {
    meta: {
      poc: "on-device-ai-fingerprint",
      version: 1,
      url: location.href,
      collectedAt: null,
      deviceLabel: "",
    },
    context: {},
    presence: {},
    surface: {},
    availability: [],
    availabilityTiming: {},
    params: null,
    active: {},
    hashes: {},
  };

  // ------------------------------------------------------- context (baseline)
  async function collectContext() {
    const n = navigator;
    const c = {
      userAgent: n.userAgent,
      platform: n.platform,
      language: n.language,
      languages: n.languages,
      hardwareConcurrency: n.hardwareConcurrency,
      deviceMemory: n.deviceMemory,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      isSecureContext: self.isSecureContext,
      crossOriginIsolated: self.crossOriginIsolated,
    };

    if (n.userAgentData?.getHighEntropyValues) {
      const r = await timed(
        "uaCH",
        () =>
          n.userAgentData.getHighEntropyValues([
            "architecture",
            "bitness",
            "model",
            "platformVersion",
            "fullVersionList",
          ]),
        T.misc
      );
      c.uaCH = r.ok ? r.value : { error: r.error };
    }

    // Gemini Nano needs lots of free disk; low disk can flip availability.
    if (n.storage?.estimate) {
      const r = await timed("storage", () => n.storage.estimate(), T.misc);
      if (r.ok) c.storageQuotaGB = round(r.value.quota / 1e9, 1);
    }

    if (n.gpu?.requestAdapter) {
      const r = await timed("webgpu", () => n.gpu.requestAdapter(), T.misc);
      if (r.ok && r.value) {
        c.webgpu = pickProps(r.value.info || {}, ["vendor", "architecture", "device", "description"]);
      } else {
        c.webgpu = r.ok ? "no adapter" : { error: r.error };
      }
    }
    return c;
  }

  // ------------------------------------------------------ passive: presence
  function probePresence() {
    const presence = {};
    const surface = {};
    for (const name of API_NAMES) {
      presence[name] = present(name);
      if (!presence[name]) continue;
      const C = self[name];
      const skip = new Set(["length", "name", "prototype", "constructor"]);
      surface[name] = {
        statics: Object.getOwnPropertyNames(C).filter((k) => !skip.has(k)).sort(),
        prototype: C.prototype
          ? Object.getOwnPropertyNames(C.prototype).filter((k) => !skip.has(k)).sort()
          : [],
      };
    }

    // Older origin-trial / flag namespaces.
    const legacyKeys = (obj) => {
      const ks = [];
      for (const k in obj) ks.push(k);
      return ks.sort();
    };
    presence["legacy:window.ai"] = "ai" in self ? legacyKeys(self.ai || {}) : false;
    presence["legacy:window.translation"] = "translation" in self ? legacyKeys(self.translation || {}) : false;
    return { presence, surface };
  }

  // -------------------------------------------------- passive: availability
  function buildAvailabilityProbes() {
    const p = [];
    const add = (api, variant, opts) => p.push({ api, variant, opts });

    add("LanguageModel", "default", undefined);
    for (const l of LM_LANGS) {
      add("LanguageModel", `text:${l}`, {
        expectedInputs: [{ type: "text", languages: [l] }],
        expectedOutputs: [{ type: "text", languages: [l] }],
      });
    }
    add("LanguageModel", "input:image", { expectedInputs: [{ type: "image" }] });
    add("LanguageModel", "input:audio", { expectedInputs: [{ type: "audio" }] });

    add("Summarizer", "default", undefined);
    for (const type of ["tldr", "key-points", "teaser", "headline"]) add("Summarizer", `type:${type}`, { type });
    for (const length of ["short", "medium", "long"]) add("Summarizer", `length:${length}`, { length });
    for (const l of ["en", "es", "ja"]) {
      add("Summarizer", `lang:${l}`, { expectedInputLanguages: [l], outputLanguage: l });
    }

    add("Writer", "default", undefined);
    add("Rewriter", "default", undefined);
    add("Proofreader", "default", undefined);

    add("LanguageDetector", "default", undefined);
    for (const l of ["en", "bn", "ja"]) add("LanguageDetector", `expect:${l}`, { expectedInputLanguages: [l] });

    for (const l of TRANSLATOR_LANGS) {
      add("Translator", `en→${l}`, { sourceLanguage: "en", targetLanguage: l });
      add("Translator", `${l}→en`, { sourceLanguage: l, targetLanguage: "en" });
    }
    return p;
  }

  async function probeAvailability() {
    const results = [];
    for (const { api, variant, opts } of buildAvailabilityProbes()) {
      if (!present(api) || typeof self[api].availability !== "function") {
        results.push({ api, variant, result: "absent", ms: null });
        continue;
      }
      const r = await timed(`${api}.availability`, () => self[api].availability(opts), T.availability);
      results.push(
        r.ok
          ? { api, variant, result: r.value, ms: r.ms }
          : { api, variant, result: null, error: r.error, errorName: r.errorName, ms: r.ms }
      );
    }
    return results;
  }

  async function probeAvailabilityTiming() {
    const out = {};
    for (const api of ["LanguageModel", "LanguageDetector", "Summarizer"]) {
      if (!present(api)) continue;
      const xs = [];
      for (let i = 0; i < TIMING_REPEATS; i++) {
        const r = await timed("availability", () => self[api].availability(), T.availability);
        if (r.ok) xs.push(r.ms);
      }
      out[api] = stats(xs);
    }
    return out;
  }

  async function probeParams() {
    if (typeof self.LanguageModel?.params !== "function") return "not exposed";
    const r = await timed("params", () => self.LanguageModel.params(), T.misc);
    if (!r.ok) return { error: r.error };
    return r.value
      ? pickProps(r.value, ["defaultTopK", "maxTopK", "defaultTemperature", "maxTemperature"])
      : null;
  }

  // --------------------------------------------------------- active probes
  const SESSION_KEYS = [
    "inputQuota", "inputUsage", "contextWindow", "contextUsage",
    "maxTokens", "tokensLeft", "tokensSoFar", "topK", "temperature",
  ];
  const LM_CREATE_OPTS = {
    expectedInputs: [{ type: "text", languages: ["en"] }],
    expectedOutputs: [{ type: "text", languages: ["en"] }],
  };

  function availabilityOf(api, variant = "default") {
    const a = report.availability.find((x) => x.api === api && x.variant === variant);
    return a ? a.result : null;
  }

  async function streamPrompt(session, prompt, measure) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), T.inference);
    const t0 = nowMs();
    let ttft = null;
    let chunks = 0;
    let text = "";
    try {
      if (typeof session.promptStreaming === "function") {
        const reader = session.promptStreaming(prompt, { signal: ac.signal }).getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (ttft === null) ttft = nowMs() - t0;
          chunks++;
          // Older Chrome streamed cumulative text, newer streams deltas.
          text = text && value.startsWith(text) ? value : text + value;
        }
      } else {
        text = await session.prompt(prompt, { signal: ac.signal });
      }
      const totalMs = nowMs() - t0;
      const out = {
        ok: true,
        ttftMs: round(ttft),
        totalMs: round(totalMs),
        chunks,
        chars: text.length,
        text,
        sha256: (await sha256Hex(text)).slice(0, 16),
      };
      if (measure) {
        const r = await timed("measure", () => measure(text), T.misc);
        if (r.ok) {
          out.outputTokens = r.value;
          const decodeMs = totalMs - (ttft ?? 0);
          if (decodeMs > 0 && r.value > 1) out.decodeTokensPerSec = round(((r.value - 1) * 1000) / decodeMs, 1);
        }
      }
      return out;
    } catch (e) {
      return { ok: false, error: errStr(e), totalMs: round(nowMs() - t0) };
    } finally {
      clearTimeout(timer);
    }
  }

  async function activeLanguageModel() {
    const out = {};
    // Try deterministic sampling first; on the web these may be rejected or ignored.
    let c = await timed(
      "LanguageModel.create",
      () => self.LanguageModel.create({ ...LM_CREATE_OPTS, topK: 1, temperature: 0 }),
      T.create
    );
    out.samplingParams = c.ok ? "accepted" : `rejected (${c.errorName})`;
    if (!c.ok) c = await timed("LanguageModel.create", () => self.LanguageModel.create(LM_CREATE_OPTS), T.create);
    out.createMs = c.ms;
    if (!c.ok) {
      out.error = c.error;
      return out;
    }
    const base = c.value;
    out.session = pickProps(base, SESSION_KEYS);

    // Name changed across Chrome versions; record which one exists.
    const measureName = ["measureContextUsage", "measureInputUsage", "countPromptTokens"].find(
      (m) => typeof base[m] === "function"
    );
    out.measureMethod = measureName || "none";
    const measure = measureName ? (s) => base[measureName](s) : null;

    out.tokenCounts = {};
    if (measure) {
      for (const [k, s] of Object.entries(TOKEN_PROBES)) {
        const r = await timed("measure", () => measure(s), T.misc);
        out.tokenCounts[k] = r.ok ? r.value : `ERR ${r.errorName}`;
      }
    } else {
      out.tokenCounts = "not exposed";
    }

    const fresh = async () =>
      typeof base.clone === "function" ? base.clone() : self.LanguageModel.create(LM_CREATE_OPTS);

    out.shortRuns = [];
    for (let i = 0; i < SHORT_RUNS; i++) {
      setStatus(`Prompt API: short prompt run ${i + 1}/${SHORT_RUNS}…`);
      const s = await fresh();
      out.shortRuns.push(await streamPrompt(s, SHORT_PROMPT, measure));
      s.destroy?.();
    }
    const okRuns = out.shortRuns.filter((r) => r.ok);
    out.shortDeterministic = okRuns.length > 1 && okRuns.every((r) => r.text === okRuns[0].text);

    setStatus("Prompt API: long prompt (throughput)…");
    const s = await fresh();
    out.longRun = await streamPrompt(s, LONG_PROMPT, measure);
    s.destroy?.();

    base.destroy?.();
    return out;
  }

  async function activeLanguageDetector() {
    const out = {};
    const c = await timed("LanguageDetector.create", () => self.LanguageDetector.create(), T.create);
    out.createMs = c.ms;
    if (!c.ok) return { ...out, error: c.error };
    const det = c.value;
    out.results = [];
    for (const text of DETECT_PROBES) {
      const r = await timed("detect", () => det.detect(text), T.misc);
      out.results.push({
        text,
        ms: r.ms,
        top: r.ok
          ? r.value.slice(0, 3).map((x) => ({ lang: x.detectedLanguage, confidence: x.confidence }))
          : `ERR ${r.errorName}`,
      });
    }
    det.destroy?.();
    return out;
  }

  async function activeSummarizer() {
    const out = {};
    const opts = {
      type: "tldr",
      length: "short",
      format: "plain-text",
      expectedInputLanguages: ["en"],
      outputLanguage: "en",
    };
    const c = await timed("Summarizer.create", () => self.Summarizer.create(opts), T.create);
    out.createMs = c.ms;
    if (!c.ok) return { ...out, error: c.error };
    const sm = c.value;
    out.inputQuota = sm.inputQuota;
    out.runs = [];
    for (let i = 0; i < 2; i++) {
      const r = await timed("summarize", () => sm.summarize(SUMMARY_TEXT), T.inference);
      out.runs.push(
        r.ok
          ? { ms: r.ms, text: r.value, sha256: (await sha256Hex(r.value)).slice(0, 16) }
          : { ms: r.ms, error: r.error }
      );
    }
    sm.destroy?.();
    return out;
  }

  async function activeTranslator() {
    const pair = report.availability.find(
      (a) => a.api === "Translator" && a.variant.startsWith("en→") && a.result === "available"
    );
    if (!pair) return "no available en→X pair";
    const opts = { sourceLanguage: "en", targetLanguage: pair.variant.slice(3) };
    const c = await timed("Translator.create", () => self.Translator.create(opts), T.create);
    if (!c.ok) return { pair: pair.variant, createMs: c.ms, error: c.error };
    const r = await timed("translate", () => c.value.translate(TRANSLATE_TEXT), T.inference);
    c.value.destroy?.();
    return {
      pair: pair.variant,
      createMs: c.ms,
      translateMs: r.ms,
      text: r.ok ? r.value : null,
      error: r.ok ? undefined : r.error,
    };
  }

  async function runActive() {
    const active = {};
    if (availabilityOf("LanguageModel") === "available") {
      setStatus("Active: Prompt API…");
      active.languageModel = await activeLanguageModel();
    } else {
      active.languageModel = `skipped (availability: ${availabilityOf("LanguageModel")})`;
    }
    if (availabilityOf("LanguageDetector") === "available") {
      setStatus("Active: Language Detector…");
      active.languageDetector = await activeLanguageDetector();
    } else {
      active.languageDetector = `skipped (availability: ${availabilityOf("LanguageDetector")})`;
    }
    if (availabilityOf("Summarizer") === "available") {
      setStatus("Active: Summarizer…");
      active.summarizer = await activeSummarizer();
    } else {
      active.summarizer = `skipped (availability: ${availabilityOf("Summarizer")})`;
    }
    if (present("Translator")) {
      setStatus("Active: Translator…");
      active.translator = await activeTranslator();
    }
    report.active = active;
  }

  // ---------------------------------------------------------------- hashes
  function passiveComponents() {
    return {
      presence: report.presence,
      surface: report.surface,
      params: report.params,
      availability: Object.fromEntries(
        report.availability.map((a) => [`${a.api}|${a.variant}`, a.result ?? `ERR:${a.errorName}`])
      ),
    };
  }

  function activeComponents() {
    const lm = report.active.languageModel;
    const det = report.active.languageDetector;
    const comp = {};
    if (lm && typeof lm === "object" && !lm.error) {
      comp.lm = {
        samplingParams: lm.samplingParams,
        session: lm.session,
        tokenCounts: lm.tokenCounts,
        // Only include outputs if they are reproducible on this device.
        shortOutput: lm.shortDeterministic ? lm.shortRuns[0].sha256 : "nondeterministic",
      };
    }
    if (det && typeof det === "object" && Array.isArray(det.results)) {
      comp.detector = det.results.map((r) => r.top);
    }
    return comp;
  }

  async function computeHashes() {
    const passive = await sha256Hex(stableStringify(passiveComponents()));
    const full = await sha256Hex(stableStringify({ p: passiveComponents(), a: activeComponents() }));
    report.hashes = { passive: passive.slice(0, 32), full: full.slice(0, 32) };
    try {
      window.localStorage.setItem("localmodel_passive", report.hashes.passive);
      window.localStorage.setItem("localmodel_full", report.hashes.full);
    } catch (e) {
      console.error("localStorage write failed:", e);
    }
  }

  // ---------------------------------------------------------------- render
  function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") e.className = v;
      else e.setAttribute(k, v);
    }
    for (const c of children) e.append(c instanceof Node ? c : String(c ?? ""));
    return e;
  }

  function table(headers, rows) {
    const t = el("table");
    t.append(el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", {}, h)))));
    const tb = el("tbody");
    for (const r of rows) tb.append(el("tr", {}, ...r.map((c) => (c instanceof Node ? el("td", {}, c) : el("td", {}, c)))));
    t.append(tb);
    return el("div", { class: "table-wrap" }, t);
  }

  function badge(v) {
    const cls = v === "available" ? "ok" : v === "downloadable" || v === "downloading" ? "warn" : "bad";
    return el("span", { class: `badge ${cls}` }, v);
  }

  function fmt(v) {
    if (v == null) return "—";
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }

  function render() {
    // Hash summary in the standard result box.
    setResult(`passive: ${report.hashes.passive}\nfull:    ${report.hashes.full}`, "Done");

    // Presence + surface
    $("presence").replaceChildren(
      table(
        ["API", "present", "statics", "prototype members"],
        Object.entries(report.presence).map(([k, v]) => [
          k,
          Array.isArray(v) ? `yes (${v.join(", ") || "empty"})` : v ? "yes" : "no",
          report.surface[k] ? report.surface[k].statics.join(", ") : "",
          report.surface[k] ? report.surface[k].prototype.join(", ") : "",
        ])
      )
    );

    // Availability
    $("availability").replaceChildren(
      table(
        ["API", "options", "availability()", "ms"],
        report.availability.map((a) => [
          a.api,
          a.variant,
          a.result ? badge(a.result) : el("span", { class: "badge bad", title: a.error || "" }, a.errorName || "error"),
          fmt(a.ms),
        ])
      )
    );

    // Timing + params
    $("timing").replaceChildren(
      table(
        ["API", "n", "min", "median", "mean", "max", "sd"],
        Object.entries(report.availabilityTiming).map(([k, s]) =>
          k === "firstCall"
            ? [`first call (cold, ${s?.api ?? "—"})`, 1, s?.ms ?? "—", "", "", "", ""]
            : s
              ? [`${k} (warm)`, s.n, s.min, s.median, s.mean, s.max, s.sd]
              : [k, "—", "", "", "", "", ""]
        )
      ),
      el("div", { class: "label" }, `LanguageModel.params(): ${fmt(report.params)}`)
    );

    // Active
    const a = report.active;
    const rows = [];
    const lm = a.languageModel;
    if (lm && typeof lm === "object") {
      rows.push(["Prompt API", "create() ms", fmt(lm.createMs)]);
      rows.push(["Prompt API", "sampling params (topK=1,temp=0)", fmt(lm.samplingParams)]);
      rows.push(["Prompt API", "session props", fmt(lm.session)]);
      rows.push(["Prompt API", "token counts", fmt(lm.tokenCounts)]);
      (lm.shortRuns || []).forEach((r, i) =>
        rows.push([
          "Prompt API",
          `short run ${i + 1}`,
          r.ok ? `TTFT ${r.ttftMs} ms, total ${r.totalMs} ms, "${r.text.trim()}" [${r.sha256}]` : r.error,
        ])
      );
      rows.push(["Prompt API", "short output deterministic", fmt(lm.shortDeterministic)]);
      if (lm.longRun) {
        const r = lm.longRun;
        rows.push([
          "Prompt API",
          "long run (throughput)",
          r.ok
            ? `TTFT ${r.ttftMs} ms, total ${r.totalMs} ms, ${r.outputTokens ?? "?"} tokens, ${r.decodeTokensPerSec ?? "?"} tok/s, ${r.chunks} chunks [${r.sha256}]`
            : r.error,
        ]);
      }
      if (lm.error) rows.push(["Prompt API", "error", lm.error]);
    } else if (lm) rows.push(["Prompt API", "", lm]);

    const det = a.languageDetector;
    if (det && typeof det === "object") {
      rows.push(["Language Detector", "create() ms", fmt(det.createMs)]);
      (det.results || []).forEach((r) =>
        rows.push([
          "Language Detector",
          `detect("${r.text}")`,
          Array.isArray(r.top) ? r.top.map((x) => `${x.lang}:${x.confidence}`).join("  ") + `  (${r.ms} ms)` : r.top,
        ])
      );
      if (det.error) rows.push(["Language Detector", "error", det.error]);
    } else if (det) rows.push(["Language Detector", "", det]);

    const sm = a.summarizer;
    if (sm && typeof sm === "object") {
      rows.push(["Summarizer", "create() ms / inputQuota", `${fmt(sm.createMs)} / ${fmt(sm.inputQuota)}`]);
      (sm.runs || []).forEach((r, i) =>
        rows.push(["Summarizer", `run ${i + 1}`, r.error ? r.error : `${r.ms} ms "${r.text}" [${r.sha256}]`])
      );
      if (sm.error) rows.push(["Summarizer", "error", sm.error]);
    } else if (sm) rows.push(["Summarizer", "", sm]);

    const tr = a.translator;
    if (tr && typeof tr === "object") {
      rows.push([
        "Translator",
        tr.pair,
        tr.error ? tr.error : `create ${tr.createMs} ms, translate ${tr.translateMs} ms: "${tr.text}"`,
      ]);
    } else if (tr) rows.push(["Translator", "", tr]);

    $("active").replaceChildren(
      rows.length ? table(["API", "probe", "value"], rows) : el("div", { class: "label" }, "Not run.")
    );

    $("context").textContent = JSON.stringify(report.context, null, 2);
    $("raw").textContent = JSON.stringify(report, null, 2);

    const needsDownload = ["LanguageModel", "LanguageDetector"].some((api) =>
      ["downloadable", "downloading"].includes(availabilityOf(api))
    );
    $("btn-download").hidden = !needsDownload;
  }

  // ------------------------------------------------------------ orchestration
  async function runPassive() {
    setStatus("Collecting baseline context…");
    report.context = await collectContext();

    setStatus("Probing API presence…");
    const { presence, surface } = probePresence();
    report.presence = presence;
    report.surface = surface;

    setStatus("Calling availability() over the option grid…");
    report.availability = await probeAvailability();

    setStatus("Timing repeated availability() calls…");
    // First call is cold (initialises the model service); later calls are cached.
    const first = report.availability.find((a) => a.ms != null);
    report.availabilityTiming = {
      firstCall: first ? { api: first.api, ms: first.ms } : null,
      ...(await probeAvailabilityTiming()),
    };

    report.params = await probeParams();
  }

  async function runAll({ active }) {
    const buttons = document.querySelectorAll("button");
    buttons.forEach((b) => (b.disabled = true));
    try {
      await runPassive();
      if (active) await runActive();
      report.meta.collectedAt = new Date().toISOString();
      await computeHashes();
      render();
      console.log("[local_model] report", JSON.stringify(report));
      setStatus(active ? "Done (passive + active)." : "Done (passive only).");
    } catch (e) {
      setError(e);
    } finally {
      buttons.forEach((b) => (b.disabled = false));
    }
  }

  // ---------------------------------------------------------------- buttons
  function exportJson() {
    report.meta.deviceLabel = $("device-label").value.trim();
    return JSON.stringify(report, null, 2);
  }

  $("btn-active").addEventListener("click", () => runAll({ active: true }));

  $("btn-download").addEventListener("click", () => {
    // create() must be called synchronously inside the click to use the
    // user activation that a model download requires.
    const progress = {};
    const show = () =>
      setStatus(
        "Downloading: " +
          Object.entries(progress)
            .map(([k, v]) => `${k} ${(v * 100).toFixed(1)}%`)
            .join(", ")
      );
    const monitorFor = (name) => (m) =>
      m.addEventListener("downloadprogress", (e) => {
        progress[name] = e.loaded;
        show();
      });
    const jobs = [];
    for (const api of ["LanguageModel", "LanguageDetector"]) {
      if (!["downloadable", "downloading"].includes(availabilityOf(api))) continue;
      progress[api] = 0;
      jobs.push(
        self[api]
          .create({ ...(api === "LanguageModel" ? LM_CREATE_OPTS : {}), monitor: monitorFor(api) })
          .then((s) => s.destroy?.())
      );
    }
    show();
    Promise.allSettled(jobs).then((rs) => {
      const failed = rs.filter((r) => r.status === "rejected");
      if (failed.length) setStatus(`Download failed: ${failed.map((f) => errStr(f.reason)).join("; ")}`);
      runAll({ active: true });
    });
  });

  $("btn-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(exportJson());
      setStatus("JSON copied to clipboard.");
    } catch (e) {
      setStatus(`Copy failed: ${errStr(e)}`);
    }
  });

  $("btn-save").addEventListener("click", () => {
    const blob = new Blob([exportJson()], { type: "application/json" });
    const a = document.createElement("a");
    const label = ($("device-label").value.trim() || "device").replace(/[^\w.-]+/g, "_");
    a.href = URL.createObjectURL(blob);
    a.download = `local_model_${label}_${Date.now()}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  // ---------------------------------------------------------------- start
  const autoActive = new URLSearchParams(location.search).get("active") !== "0";
  runAll({ active: autoActive });
})();
