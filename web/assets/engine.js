/* IntelPulse browser engine.
 *
 * A faithful port of the backend's extraction, scoring and report modules so
 * that demo mode behaves exactly like the real pipeline — same regexes, same
 * weights, same authority floor, same verdict bands. Only the intelligence is
 * different: demo mode reads the bundled synthetic dataset, live mode calls the
 * FastAPI service. Keeping one formula in two places is a deliberate trade:
 * the static GitHub Pages build has to run with no backend at all.
 */
(function (root, factory) {
  const api = factory();
  root.IntelPulseEngine = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // ---------------------------------------------------------------- weights
  const WEIGHTS = {
    abuseipdb: 1.0, otx: 0.9, threatfox: 1.2, urlhaus: 1.1,
    local_blocklist: 1.0, greynoise: 0.6, geoip: 0.25
  };
  const AUTHORITY = {
    threatfox: 0.95, urlhaus: 0.95, local_blocklist: 0.9,
    abuseipdb: 0.8, otx: 0.7, greynoise: 0.5, geoip: 0.3
  };
  const THRESHOLDS = { low: 15, medium: 40, high: 70, critical: 85 };
  const GREYNOISE_BENIGN_MULTIPLIER = 0.45;

  const ATTACK = {
    T1071: ["Application Layer Protocol", "Command and Control"],
    "T1071.001": ["Web Protocols", "Command and Control"],
    T1090: ["Proxy", "Command and Control"],
    T1105: ["Ingress Tool Transfer", "Command and Control"],
    T1566: ["Phishing", "Initial Access"],
    "T1566.002": ["Spearphishing Link", "Initial Access"],
    T1190: ["Exploit Public-Facing Application", "Initial Access"],
    T1110: ["Brute Force", "Credential Access"],
    T1595: ["Active Scanning", "Reconnaissance"],
    "T1583.003": ["Acquire Infrastructure: Virtual Private Server", "Resource Development"],
    T1486: ["Data Encrypted for Impact", "Impact"],
    T1498: ["Network Denial of Service", "Impact"],
    T1499: ["Endpoint Denial of Service", "Impact"],
    T1078: ["Valid Accounts", "Defense Evasion"]
  };
  const TAG_TECHNIQUES = [
    ["brute", "T1110"], ["ssh", "T1110"], ["phish", "T1566"], ["ransom", "T1486"],
    ["locker", "T1486"], ["ddos", "T1498"], ["dos attack", "T1499"], ["port scan", "T1595"],
    ["scanner", "T1595"], ["web app attack", "T1190"], ["sql injection", "T1190"],
    ["exploit", "T1190"], ["proxy", "T1090"], ["tor", "T1090"], ["c2", "T1071"],
    ["botnet", "T1071"], ["cobalt", "T1071"], ["loader", "T1105"], ["stealer", "T1105"],
    ["payload", "T1105"]
  ];

  // ------------------------------------------------------------- extraction
  const URL_RE = /\bhttps?:\/\/[^\s<>"'\)\]\},]{4,2048}/gi;
  const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const HASH_RE = /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi;
  /* Bounded like the backend's, for the same reason: unbounded, both were
     quadratic on "a.a.a.a…" and a long paste froze the tab. */
  const EMAIL_RE = /\b[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,24}\b/gi;
  const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
  const DOMAIN_RE = /\b(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.){1,20}[a-z]{2,24}\b/gi;

  const FILE_SUFFIXES = new Set(("exe dll sys bat cmd ps1 vbs js jar lnk scr doc docx xls xlsx " +
    "ppt pptx pdf zip rar 7z png jpg jpeg gif svg ico css log txt tmp dat bin iso msi conf cfg " +
    "ini xml yml yaml json py sh db sqlite local localdomain internal corp lan home arpa invalid " +
    "example test").split(" "));

  const JSON_IOC_KEYS = new Set(["ip", "ipaddress", "ip_address", "src_ip", "dst_ip", "sourceip",
    "destinationip", "src", "dst", "remoteaddress", "remoteip", "clientip", "host", "hostname",
    "domain", "url", "uri", "request_url", "referer", "hash", "sha256", "sha1", "md5", "filehash",
    "hashes", "process_hash", "sender", "from", "recipient", "to", "email", "cve"]);

  /* RFC 5737 / 3849 documentation ranges. Non-routable in reality, which is why
     the bundled demo dataset uses them — nothing here can defame a real host. */
  const DOC_RANGES = [[[192, 0, 2], 24], [[198, 51, 100], 24], [[203, 0, 113], 24]];

  function refang(text) {
    return String(text)
      .replace(/\[\s*\.\s*\]/g, ".").replace(/\(\s*\.\s*\)/g, ".").replace(/\{\s*\.\s*\}/g, ".")
      .replace(/\s+dot\s+/gi, ".").replace(/\[\s*:\s*\]/g, ":")
      .replace(/\[\s*@\s*\]/g, "@").replace(/\(\s*@\s*\)/g, "@")
      .replace(/\bhxxps/gi, "https").replace(/\bhxxp/gi, "http")
      .replace(/\[\s*(https?)\s*\]/gi, "$1");
  }

  function defang(value) {
    return String(value).replace(/http/g, "hxxp").replace(/\./g, "[.]");
  }

  function ipOctets(value) {
    const parts = value.split(".");
    if (parts.length !== 4) return null;
    const nums = parts.map(Number);
    if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    return nums;
  }

  function isDocumentationIp(nums) {
    return DOC_RANGES.some(([prefix]) =>
      prefix.every((octet, index) => octet === nums[index]));
  }

  function isPublicIp(value, options) {
    const nums = ipOctets(value);
    if (!nums) return false;
    const [a, b] = nums;
    if (options && options.allowDocumentation && isDocumentationIp(nums)) return true;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;          // this-net, private, loopback, multicast/reserved
    if (a === 172 && b >= 16 && b <= 31) return false;                        // RFC1918
    if (a === 192 && b === 168) return false;                                 // RFC1918
    if (a === 169 && b === 254) return false;                                 // link-local
    if (a === 100 && b >= 64 && b <= 127) return false;                       // CGNAT
    if (a === 198 && (b === 18 || b === 19)) return false;                    // benchmarking
    if (isDocumentationIp(nums)) return false;                                // documentation
    return true;
  }

  function isPlausibleDomain(value) {
    const host = String(value).replace(/^\.+|\.+$/g, "").toLowerCase();
    if (!host.includes(".") || host.length > 253) return false;
    const tld = host.split(".").pop();
    if (FILE_SUFFIXES.has(tld) || /^\d+$/.test(tld)) return false;
    return !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
  }

  function urlHost(url) {
    const match = /^https?:\/\/(?:[^/@\s]+@)?([^/:\s]+)/i.exec(url);
    return match ? match[1].toLowerCase() : null;
  }

  function classify(value, options) {
    const token = String(value).trim().replace(/[,;]+$/, "");
    if (!token) return null;
    if (new RegExp("^" + CVE_RE.source + "$", "i").test(token)) return "cve";
    if (/^https?:\/\/\S+$/i.test(token)) return "url";
    if (/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(token)) return "hash";
    if (/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}$/i.test(token)) return "email";
    if (ipOctets(token)) return isPublicIp(token, options) ? "ip" : null;
    return isPlausibleDomain(token) ? "domain" : null;
  }

  function walkJson(node, out) {
    if (Array.isArray(node)) { node.forEach((item) => walkJson(item, out)); return; }
    if (node && typeof node === "object") {
      Object.keys(node).forEach((key) => {
        const value = node[key];
        if (typeof value === "string" && JSON_IOC_KEYS.has(key.toLowerCase().replace(/-/g, "_"))) {
          out.push(value);
        }
        walkJson(value, out);
      });
      return;
    }
    if (typeof node === "string") out.push(node);
  }

  function contextFor(text, token) {
    const index = text.indexOf(token);
    if (index < 0) return "";
    const start = text.lastIndexOf("\n", index) + 1;
    const end = text.indexOf("\n", index);
    return text.slice(start, end === -1 ? text.length : end).trim().slice(0, 220);
  }

  function extract(text, options) {
    options = options || {};
    if (!text) return [];
    const candidates = [];
    const trimmed = String(text).trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      try { walkJson(JSON.parse(trimmed), candidates); }
      catch (_) { candidates.push(text); }
    } else {
      candidates.push(text);
    }

    const haystack = refang(candidates.join("\n"));
    const found = new Map();

    function add(raw, type, normalised) {
      let value = String(normalised || raw).trim().replace(/[.,;)]+$/, "");
      if (type !== "url" && type !== "cve") value = value.toLowerCase();
      if (type === "cve") value = value.toUpperCase();
      const key = type === "url" ? value : value.toLowerCase();
      if (found.has(key)) return;
      found.set(key, { value: value, type: type, original: raw, context: contextFor(haystack, raw) });
    }

    const urls = haystack.match(URL_RE) || [];
    urls.forEach((url) => {
      add(url, "url");
      const host = urlHost(url);
      if (host && ipOctets(host)) { if (isPublicIp(host, options)) add(host, "ip"); }
      else if (host && isPlausibleDomain(host)) add(host, "domain");
    });

    let masked = haystack;
    urls.forEach((url) => { masked = masked.split(url).join(" ".repeat(url.length)); });

    (masked.match(CVE_RE) || []).forEach((m) => add(m, "cve", m.toUpperCase()));
    (masked.match(HASH_RE) || []).forEach((m) => add(m, "hash", m.toLowerCase()));
    (masked.match(EMAIL_RE) || []).forEach((m) => {
      add(m, "email", m.toLowerCase());
      const domain = m.split("@")[1];
      if (isPlausibleDomain(domain)) add(domain, "domain");
    });
    (masked.match(IPV4_RE) || []).forEach((m) => { if (isPublicIp(m, options)) add(m, "ip"); });
    (masked.match(DOMAIN_RE) || []).forEach((m) => { if (isPlausibleDomain(m)) add(m, "domain"); });

    const order = { ip: 0, domain: 1, url: 2, hash: 3, email: 4, cve: 5 };
    const list = Array.from(found.values()).sort((a, b) =>
      (order[a.type] - order[b.type]) || a.value.localeCompare(b.value));
    return options.limit ? list.slice(0, options.limit) : list;
  }

  // ---------------------------------------------------------------- scoring
  function verdictFor(score) {
    if (score >= THRESHOLDS.critical) return "critical";
    if (score >= THRESHOLDS.high) return "high";
    if (score >= THRESHOLDS.medium) return "medium";
    if (score >= THRESHOLDS.low) return "low";
    return "informational";
  }

  function deriveAttackIds(sources) {
    const ids = [];
    const blob = [];
    sources.forEach((source) => {
      (source.attack_ids || []).forEach((id) => { if (!ids.includes(id)) ids.push(id); });
      (source.tags || []).forEach((tag) => blob.push(String(tag).toLowerCase()));
      (source.malware_families || []).forEach((family) => blob.push(String(family).toLowerCase()));
      ["top_categories", "threat_types"].forEach((key) => {
        const value = (source.facts || {})[key];
        if (Array.isArray(value)) value.forEach((entry) => blob.push(String(entry).toLowerCase()));
      });
    });
    const text = blob.join(" ");
    TAG_TECHNIQUES.forEach(([needle, id]) => {
      if (text.includes(needle) && !ids.includes(id)) ids.push(id);
    });
    return ids;
  }

  function describeTechniques(ids) {
    return ids.map((id) => {
      const entry = ATTACK[id] || ["Unmapped technique", "Unknown"];
      return {
        id: id, name: entry[0], tactic: entry[1],
        url: "https://attack.mitre.org/techniques/" + id.replace(".", "/") + "/"
      };
    });
  }

  function scoreIndicator(indicator, sources, listEntry) {
    const answered = sources.filter((s) => s.status === "ok" || s.status === "clean");
    const contributions = [];
    const modifiers = [];
    let weightedSum = 0, weightTotal = 0, authorityFloor = 0;

    answered.forEach((source) => {
      (source.signals || []).forEach((signal) => {
        const weight = WEIGHTS[signal.key] !== undefined ? WEIGHTS[signal.key] : 0.5;
        if (weight <= 0) return;
        const value = Math.max(0, Math.min(1, Number(signal.value) || 0));
        const authority = AUTHORITY[signal.key] !== undefined ? AUTHORITY[signal.key] : 0.5;
        weightedSum += weight * value;
        weightTotal += weight;
        authorityFloor = Math.max(authorityFloor, value * authority);
        contributions.push({
          provider: source.provider, signal: Number(value.toFixed(3)), weight: weight,
          weighted: Number((weight * value).toFixed(3)), rationale: signal.rationale || ""
        });
      });
    });

    const weightedMean = weightTotal ? weightedSum / weightTotal : 0;
    let score = Math.max(weightedMean, authorityFloor) * 100;

    const greynoise = answered.find((s) => s.provider === "greynoise");
    if (greynoise && (greynoise.facts || {}).classification === "benign") {
      score *= GREYNOISE_BENIGN_MULTIPLIER;
      modifiers.push("GreyNoise classifies this as benign internet background noise (" +
        ((greynoise.facts || {}).actor || "known scanner") + ") — score damped x" +
        GREYNOISE_BENIGN_MULTIPLIER);
    }
    if (greynoise && (greynoise.facts || {}).riot) {
      score = Math.min(score, 45);
      modifiers.push("GreyNoise RIOT: common business service, capped below High");
    }
    if (listEntry && listEntry.list_type === "allow") {
      score = 0;
      modifiers.push("analyst allowlist: " + (listEntry.reason || "no reason recorded"));
    } else if (listEntry && listEntry.list_type === "block") {
      score = Math.max(score, 90);
      modifiers.push("analyst blocklist: " + (listEntry.reason || "no reason recorded"));
    }

    const finalScore = Math.round(Math.max(0, Math.min(100, score)));
    const applicable = sources.filter((s) => s.status !== "skipped");
    const coverage = applicable.length ? answered.length / applicable.length : 0;
    const corroborating = contributions.filter((c) => c.signal >= 0.5).length;
    const agreement = finalScore >= THRESHOLDS.medium
      ? Math.min(1, corroborating / 2)
      : Math.min(1, answered.length / 3);
    let confidence = Math.min(1, 0.2 + 0.5 * coverage + 0.3 * agreement);
    if (listEntry) confidence = 1;

    const tags = [], families = [];
    answered.forEach((source) => {
      (source.tags || []).forEach((tag) => { if (!tags.includes(tag)) tags.push(tag); });
      (source.malware_families || []).forEach((f) => { if (!families.includes(f)) families.push(f); });
    });
    contributions.sort((a, b) => b.weighted - a.weighted);

    return {
      value: indicator.value,
      type: indicator.type,
      context: indicator.context || "",
      score: finalScore,
      verdict: (listEntry && listEntry.list_type === "allow") ? "allowlisted" : verdictFor(finalScore),
      confidence: Number(confidence.toFixed(2)),
      evidence: contributions,
      modifiers: modifiers,
      tags: tags.slice(0, 12),
      malware_families: families.slice(0, 8),
      attack_techniques: describeTechniques(deriveAttackIds(answered)),
      providers_queried: sources.length,
      providers_answered: answered.length,
      containment: containmentActions({
        type: indicator.type,
        verdict: (listEntry && listEntry.list_type === "allow") ? "allowlisted" : verdictFor(finalScore),
        malware_families: families
      }),
      sources: sources
    };
  }

  // -------------------------------------------------------------- reporting
  const SEVERITY_SLA = {
    critical: "P1 — contain within 1 hour",
    high: "P2 — contain within 4 hours",
    medium: "P3 — investigate within 1 business day",
    low: "P4 — monitor",
    informational: "P5 — no action, record only",
    allowlisted: "closed — allowlisted by the SOC"
  };

  const CONTAINMENT = {
    ip: ["Block the address at the perimeter firewall and on egress proxies.",
         "Search SIEM/NetFlow for the last 30 days of traffic to this address and list every internal host that talked to it.",
         "If any internal host communicated with it, isolate the host and capture volatile memory before reimaging."],
    domain: ["Sinkhole or block the domain on the DNS resolver and secure web gateway.",
             "Query DNS logs for the last 30 days for resolution attempts and identify the requesting hosts.",
             "Add the domain and its known subdomains to the email gateway blocklist."],
    url: ["Block the full URL and its parent domain on the web proxy.",
          "Pull proxy logs for anyone who fetched it; treat a 200 response as a suspected download.",
          "If a user clicked it, reset their credentials and revoke active sessions and OAuth tokens."],
    hash: ["Add the hash to the EDR blocklist and trigger an estate-wide hash sweep.",
           "Quarantine any endpoint where the file is present and preserve the sample for analysis.",
           "Identify the delivery vector (email attachment, USB, download) before closing the ticket."],
    email: ["Block the sender address and its domain at the mail gateway.",
            "Run a mailbox search-and-purge for messages from this sender.",
            "Notify recipients and force password resets where credentials may have been entered."],
    cve: ["Confirm exposure with an authenticated vulnerability scan of the affected estate.",
          "Apply the vendor patch or documented mitigation within the SLA for its CVSS band.",
          "Add detection for known exploitation attempts against the affected service."]
  };
  const NO_ACTION = ["No containment action required — record the triage result against the ticket and close.",
                     "If this indicator recurs with a higher score, re-open and re-triage."];

  function containmentActions(indicator) {
    if (["informational", "allowlisted", "low"].includes(indicator.verdict)) return NO_ACTION.slice();
    const actions = (CONTAINMENT[indicator.type] || NO_ACTION).slice();
    if ((indicator.malware_families || []).length) {
      actions.push("Hunt for the known TTPs of " + indicator.malware_families.slice(0, 3).join(", ") +
        " across endpoints and identity logs.");
    }
    if (indicator.verdict === "critical") {
      actions.push("Raise a major-incident bridge and notify the on-call incident manager.");
    }
    return actions;
  }

  function scoreBar(score) {
    const filled = Math.round(score / 10);
    return "█".repeat(filled) + "░".repeat(10 - filled);
  }

  /* Untrusted text on its way into a label or a Markdown ticket: a port of
     backend/app/text.py. A newline is what lets a title forge a section of the
     ticket, a bracket makes a link or an image, a scheme is one click away. */
  const INVISIBLE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g;
  function cleanLabel(value, limit) {
    limit = limit || 200;
    const text = String(value == null ? "" : value).replace(INVISIBLE, " ").replace(/\s+/g, " ").trim();
    return text.length <= limit ? text : text.slice(0, limit - 1).replace(/\s+$/, "") + "\u2026";
  }
  function mdText(value, limit) {
    return cleanLabel(value, limit || 300)
      .replace(/\bhttp(s?):\/\//gi, (m, s) => "hxxp" + s + "://")
      .replace(/([\\`\[\]<>|])/g, "\\$1");
  }
  const code = (value) => "`" + defang(String(value)).replace(/`/g, "%60") + "`";

  function executiveSummary(indicators, verdict, score, markdown) {
    const label = markdown ? mdText : cleanLabel;
    if (!indicators.length) return "No indicators were extracted from the supplied input.";
    const actionable = indicators.filter((i) => i.score >= THRESHOLDS.medium);
    const families = Array.from(new Set([].concat.apply([], indicators.map((i) => i.malware_families || []))));
    let lead = indicators.length + " indicator(s) were triaged across the configured intelligence sources. " +
      "The highest composite score is " + score + "/100 (" + verdict.toUpperCase() + ").";
    if (actionable.length) {
      const worst = actionable.reduce((a, b) => (a.score >= b.score ? a : b));
      lead += " " + actionable.length + " indicator(s) are actionable, led by " + code(worst.value) +
        " (" + worst.verdict.toUpperCase() + ", " + worst.score + "/100, confidence " +
        Math.round(worst.confidence * 100) + "%).";
    } else {
      lead += " No indicator reached the actionable threshold; treat this as informational.";
    }
    if (families.length) lead += " Associated malware/activity: " + families.slice(0, 4).map((f) => label(f, 80)).join(", ") + ".";
    return lead;
  }

  function toMarkdown(result, options) {
    options = options || {};
    const now = new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC";
    const sorted = result.indicators.slice().sort((a, b) => b.score - a.score);
    const lines = [
      "# SOC Triage Report — " + mdText(result.title, 200), "",
      "| Field | Value |", "| --- | --- |",
      "| Case ID | " + code(result.case_id) + " |",
      "| Generated | " + now + " |",
      "| Analyst | " + (options.analyst ? mdText(options.analyst, 120) : "IntelPulse (automated)") + " |",
      "| Severity | **" + result.verdict.toUpperCase() + "** (" + result.score + "/100) |",
      "| Priority | " + (SEVERITY_SLA[result.verdict] || "P4") + " |",
      "| Indicators | " + result.indicators.length + " |",
      "| Enrichment time | " + result.duration_ms + " ms |",
      "", "## 1. Executive summary", "",
      /* recomputed, escaped: a live result's summary is plain text from the API */
      executiveSummary(result.indicators, result.verdict, result.score, true),
      "", "## 2. Indicators observed", "",
      "| Indicator | Type | Score | Verdict | Confidence | Sources agreeing |",
      "| --- | --- | --- | --- | --- | --- |"
    ];
    sorted.forEach((i) => {
      const agreeing = (i.evidence || []).filter((e) => e.signal >= 0.5).length;
      lines.push("| " + code(i.value) + " | " + mdText(i.type, 10) + " | " + i.score + "/100 `" +
        scoreBar(i.score) + "` | **" + i.verdict.toUpperCase() + "** | " +
        Math.round(i.confidence * 100) + "% | " + agreeing + "/" + i.providers_answered + " |");
    });

    lines.push("", "## 3. Evidence and attribution", "");
    sorted.forEach((i) => {
      lines.push("### " + code(i.value) + " — " + i.verdict.toUpperCase() + " (" + i.score + "/100)", "");
      if ((i.malware_families || []).length) lines.push("- **Malware / campaign:** " + i.malware_families.map((f) => mdText(f, 80)).join(", "));
      if ((i.attack_techniques || []).length) {
        lines.push("- **MITRE ATT&CK:** " + i.attack_techniques.slice(0, 6)
          .map((t) => mdText(t.id, 20) + " (" + mdText(t.name, 80) + ")").join(", "));
      }
      if ((i.tags || []).length) lines.push("- **Tags:** " + i.tags.slice(0, 10).map((t) => mdText(t, 60)).join(", "));
      (i.evidence || []).forEach((e) => {
        lines.push("- **" + mdText(e.provider, 40) + "** (signal " + Number(e.signal).toFixed(2) + ", weight " + Number(e.weight) + "): " + mdText(e.rationale, 400));
      });
      (i.modifiers || []).forEach((m) => lines.push("- **Modifier:** " + mdText(m, 300)));
      lines.push("");
    });

    lines.push("## 4. Recommended containment actions", "");
    const seen = new Set();
    sorted.forEach((i) => {
      if (["informational", "allowlisted"].includes(i.verdict)) return;
      lines.push("**" + code(i.value) + " (" + i.verdict.toUpperCase() + ")**");
      (i.containment || []).forEach((action) => {
        if (seen.has(action)) return;
        seen.add(action);
        lines.push("- [ ] " + action);
      });
      lines.push("");
    });
    if (!seen.size) { NO_ACTION.forEach((a) => lines.push("- [x] " + a)); lines.push(""); }

    const queried = result.indicators.reduce((sum, i) => sum + (i.providers_queried || 0), 0);
    const answered = result.indicators.reduce((sum, i) => sum + (i.providers_answered || 0), 0);
    lines.push("## 5. Notes", "",
      "- **Source coverage:** " + answered + "/" + queried + " provider lookups returned data. " +
      "Unconfigured or failing sources are listed as skipped/error in the platform UI; " +
      "a low-coverage verdict should be treated as provisional.",
      "- Indicators are defanged in this report; refang before use in tooling.",
      "- Scores are a weighted composite of the sources listed above, not a single vendor verdict.",
      "- Confidence reflects source coverage and agreement, not certainty of maliciousness.", "");
    if (options.demo) {
      lines.push("> ⚠️ **Demo mode:** this report was produced from IntelPulse's bundled synthetic " +
        "dataset in the browser. No live vendor API was queried.", "");
    }
    lines.push("_Generated by IntelPulse · case `" + result.case_id + "`_");
    return lines.join("\n");
  }

  function toTicketJson(result, options) {
    options = options || {};
    return {
      case_id: result.case_id,
      title: result.title,
      generated_at: new Date().toISOString(),
      analyst: options.analyst || "IntelPulse (automated)",
      mode: options.demo ? "demo (synthetic dataset)" : "live",
      severity: result.verdict,
      priority: SEVERITY_SLA[result.verdict] || "P4",
      score: result.score,
      summary: result.summary,
      indicators: result.indicators.slice().sort((a, b) => b.score - a.score).map((i) => ({
        value: i.value, defanged: defang(i.value), type: i.type, score: i.score,
        verdict: i.verdict, confidence: i.confidence, malware_families: i.malware_families,
        attack_techniques: i.attack_techniques, tags: i.tags, evidence: i.evidence,
        modifiers: i.modifiers, containment: i.containment
      }))
    };
  }

  // ------------------------------------------------------------------ graph
  const NODE_COLORS = {
    critical: "#ff4d4d", high: "#ff8c42", medium: "#ffd166",
    low: "#4cc9f0", informational: "#7d8597", allowlisted: "#3ddc97"
  };
  const IOC_KINDS = ["ip", "domain", "url", "hash", "email", "cve"];

  function buildGraph(indicators) {
    const nodes = new Map();
    const edges = [];
    const addNode = (id, label, kind, extra) => {
      if (nodes.has(id)) { Object.assign(nodes.get(id).data, extra || {}); return; }
      nodes.set(id, { data: Object.assign({ id: id, label: String(label).slice(0, 48), kind: kind }, extra || {}) });
    };
    const addEdge = (source, target, relation, confidence) => {
      const id = source + "->" + target + ":" + relation;
      if (edges.some((e) => e.data.id === id)) return;
      edges.push({ data: { id: id, source: source, target: target, label: relation.replace(/_/g, " "), confidence: confidence } });
    };

    indicators.forEach((indicator) => {
      const nodeId = "ioc:" + indicator.value;
      addNode(nodeId, indicator.value, indicator.type, {
        score: indicator.score, verdict: indicator.verdict,
        color: NODE_COLORS[indicator.verdict] || "#7d8597", root: true
      });
      (indicator.sources || []).forEach((source) => {
        if (source.status !== "ok" && source.status !== "clean") return;
        (source.relations || []).forEach((relation) => {
          const targetId = (IOC_KINDS.includes(relation.target_type) ? "ioc:" : relation.target_type + ":") + relation.target;
          addNode(targetId, relation.target, relation.target_type, {
            color: relation.confidence > 0.7 ? NODE_COLORS.medium : NODE_COLORS.informational,
            source_provider: source.provider
          });
          addEdge(nodeId, targetId, relation.relation, relation.confidence);
        });
      });
    });
    return { nodes: Array.from(nodes.values()), edges: edges };
  }

  // ------------------------------------------------------------- demo mode
  function uuid() {
    if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  const ALL_PROVIDERS = [
    { provider: "abuseipdb", label: "AbuseIPDB", types: ["ip"] },
    { provider: "otx", label: "AlienVault OTX", types: ["ip", "domain", "url", "hash"] },
    { provider: "threatfox", label: "ThreatFox (abuse.ch)", types: ["ip", "domain", "url", "hash"] },
    { provider: "urlhaus", label: "URLhaus (abuse.ch)", types: ["ip", "domain", "url", "hash"] },
    { provider: "greynoise", label: "GreyNoise", types: ["ip"] },
    { provider: "local_blocklist", label: "Local historical feeds", types: ["ip", "domain", "url", "hash"] },
    { provider: "geoip", label: "MaxMind GeoLite2 (offline)", types: ["ip"] },
    { provider: "nvd", label: "NVD (offline)", types: ["cve"] }
  ];

  /* Demo triage never invents vendor data: an indicator outside the bundled
     dataset comes back explicitly "no sample data", not a fabricated score. */
  /* ─────────────────────────────── what changed since the last triage
   * A faithful port of backend/app/services/history.py. Same band order, same
   * rules about which sources count as answering, same summary wording — so a
   * demo-mode diff reads exactly like a live one. Pinned by the parity tests
   * in web/tests/engine.test.mjs.
   */
  const BANDS = ["informational", "low", "medium", "high", "critical"];
  const ANSWERED = ["ok", "clean"];

  /* The comparable shape of one indicator, out of a scored result. A provider
     that was skipped or errored did not answer: counting it would report a
     vendor outage as an intelligence change. */
  function snapshotOf(scored) {
    if (!scored) return { score: 0, verdict: "informational", answering: [], malware_families: [], attack_ids: [] };
    const uniq = (list) => Array.from(new Set((list || []).map(String))).sort();
    const attack = (scored.attack_techniques || []).map((t) => (t && t.id ? t.id : t));
    return {
      score: Math.round(scored.score || 0),
      verdict: String(scored.verdict || "informational"),
      answering: uniq((scored.sources || [])
        .filter((s) => s && ANSWERED.indexOf(s.status) !== -1 && s.provider)
        .map((s) => s.provider)),
      malware_families: uniq(scored.malware_families),
      attack_ids: uniq(attack)
    };
  }

  function summariseDiff(d) {
    if (d.first_seen) return "First time this indicator has been triaged.";
    if (!d.changed) return "No change since the last triage.";
    const parts = [];
    if (d.verdict_changed && d.escalated) parts.push("Escalated from " + d.previous_verdict + " to " + d.verdict);
    else if (d.verdict_changed && d.de_escalated) parts.push("Dropped from " + d.previous_verdict + " to " + d.verdict);
    else if (d.verdict_changed) parts.push("Band changed from " + d.previous_verdict + " to " + d.verdict);
    else if (d.score_delta) parts.push("Score " + (d.score_delta > 0 ? "up " : "down ") + Math.abs(d.score_delta) + " to " + d.score);
    if (d.new_malware_families.length) parts.push("new malware: " + d.new_malware_families.join(", "));
    if (d.sources_added.length) parts.push("now answering: " + d.sources_added.join(", "));
    if (d.sources_removed.length) parts.push("stopped answering: " + d.sources_removed.join(", "));
    if (d.new_attack_ids.length) parts.push("new techniques: " + d.new_attack_ids.join(", "));
    return parts.join("; ") + ".";
  }

  function diffSnapshots(current, previous, meta) {
    meta = meta || {};
    const missing = (a, b) => a.filter((x) => b.indexOf(x) === -1);
    const d = {
      value: meta.value || "",
      score: current.score, verdict: current.verdict,
      first_seen: false, changed: false,
      previous_case_id: meta.previous_case_id || null,
      previous_at: meta.previous_at || null,
      previous_score: null, previous_verdict: null,
      score_delta: 0, verdict_changed: false, escalated: false, de_escalated: false,
      sources_added: [], sources_removed: [],
      new_malware_families: [], new_attack_ids: [], summary: ""
    };
    if (!previous) {
      d.first_seen = true;
      d.summary = summariseDiff(d);
      return d;
    }
    d.previous_score = previous.score;
    d.previous_verdict = previous.verdict;
    d.score_delta = current.score - previous.score;
    d.verdict_changed = current.verdict !== previous.verdict;
    if (d.verdict_changed) {
      const now = BANDS.indexOf(current.verdict), before = BANDS.indexOf(previous.verdict);
      /* A band out of storage may predate this release: it compares as changed
         without claiming a direction. */
      if (now !== -1 && before !== -1) { d.escalated = now > before; d.de_escalated = now < before; }
    }
    d.sources_added = missing(current.answering, previous.answering);
    d.sources_removed = missing(previous.answering, current.answering);
    d.new_malware_families = missing(current.malware_families, previous.malware_families);
    d.new_attack_ids = missing(current.attack_ids, previous.attack_ids);
    d.changed = Boolean(d.score_delta || d.verdict_changed || d.sources_added.length ||
      d.sources_removed.length || d.new_malware_families.length || d.new_attack_ids.length);
    d.summary = summariseDiff(d);
    return d;
  }

  function demoTriage(text, dataset, options) {
    options = options || {};
    const started = Date.now();
    const indicators = extract(text, { limit: options.limit || 100, allowDocumentation: true });
    const lists = options.lists || [];

    const scored = indicators.map((indicator) => {
      const key = indicator.type === "url" ? indicator.value : indicator.value.toLowerCase();
      const known = (dataset.intel || {})[key] || (dataset.intel || {})[indicator.value.toLowerCase()];
      const applicable = ALL_PROVIDERS.filter((p) => p.types.includes(indicator.type));
      let sources;
      if (known) {
        const byName = new Map(known.map((entry) => [entry.provider, entry]));
        sources = applicable.map((p) => byName.get(p.provider) || {
          provider: p.provider, label: p.label, status: "clean", facts: {},
          signals: [{ key: p.provider === "nvd" ? "otx" : p.provider, value: 0, rationale: "no record in the bundled sample dataset" }],
          relations: [], tags: [], malware_families: [], attack_ids: []
        });
      } else {
        sources = applicable.map((p) => ({
          provider: p.provider, label: p.label, status: "skipped",
          error: "demo mode: no sample data for this indicator — connect a live backend",
          facts: {}, signals: [], relations: [], tags: [], malware_families: [], attack_ids: []
        }));
      }
      const listEntry = lists.find((entry) => entry.value.toLowerCase() === indicator.value.toLowerCase());
      return scoreIndicator(indicator, sources, listEntry);
    });

    const score = scored.reduce((max, i) => Math.max(max, i.score), 0);
    const verdict = verdictFor(score);
    return {
      case_id: uuid(),
      title: options.title || "Demo triage",
      verdict: verdict,
      score: score,
      duration_ms: Date.now() - started,
      cache_hits: 0,
      indicator_count: scored.length,
      summary: executiveSummary(scored, verdict, score),
      indicators: scored,
      graph: buildGraph(scored),
      mode: "demo"
    };
  }

  return {
    WEIGHTS: WEIGHTS, AUTHORITY: AUTHORITY, THRESHOLDS: THRESHOLDS, ATTACK: ATTACK,
    refang: refang, defang: defang, extract: extract, classify: classify,
    isPublicIp: isPublicIp, isPlausibleDomain: isPlausibleDomain,
    scoreIndicator: scoreIndicator, verdictFor: verdictFor, deriveAttackIds: deriveAttackIds,
    containmentActions: containmentActions, executiveSummary: executiveSummary,
    toMarkdown: toMarkdown, toTicketJson: toTicketJson, buildGraph: buildGraph,
    demoTriage: demoTriage, scoreBar: scoreBar, SEVERITY_SLA: SEVERITY_SLA, uuid: uuid,
    BANDS: BANDS, snapshotOf: snapshotOf, diffSnapshots: diffSnapshots,
    cleanLabel: cleanLabel, mdText: mdText
  };
});
