/* Bundled sample intelligence for offline/demo mode.
 *
 * IMPORTANT: every record below is SYNTHETIC. The addresses are RFC 5737
 * documentation ranges and the domains are RFC 2606 reserved names, so nothing
 * here attributes malicious activity to a real host. Demo mode exists so the
 * GitHub Pages deployment is usable without a backend or API keys; connect a
 * running IntelPulse API for real vendor data.
 */
(typeof window !== "undefined" ? window : globalThis).INTELPULSE_DEMO = {
  scenarios: [
    {
      id: "firewall",
      label: "Firewall syslog burst",
      text: `Sep 18 02:14:11 fw-edge-01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.10 DST=10.20.4.15 PROTO=TCP SPT=44321 DPT=445
Sep 18 02:14:19 fw-edge-01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.10 DST=10.20.4.16 PROTO=TCP SPT=44322 DPT=3389
Sep 18 02:17:02 fw-edge-01 kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.42 DST=10.20.4.15 PROTO=TCP SPT=51002 DPT=22
Sep 18 02:19:47 proxy-01 squid[1182]: TCP_MISS/200 CONNECT 203.0.113.200:443 - scanner probe
Sep 18 02:21:33 dc-01 Security: 4625 logon failure user=svc_backup src=198.51.100.42`
    },
    {
      id: "phishing",
      label: "Phishing email triage",
      text: `Received: from mail.mailer.example.net ([192.0.2.77])
From: "IT Service Desk" <it-helpdesk@secure-login.example.com>
Subject: [Action Required] Mailbox quota exceeded
Reported link: hxxps://secure-login[.]example[.]com/owa/session?id=8812
Attachment SHA256: 5d41402abc4b2a76b9719d911017c592a1b2c3d4e5f60718293a4b5c6d7e8f90
Reporting user clicked the link at 09:41 GMT.`
    },
    {
      id: "edr",
      label: "EDR alert (JSON)",
      text: `{
  "alert_id": "EDR-2026-0918-441",
  "host": "LON-WS-0442",
  "user": "j.okafor",
  "process": "powershell.exe",
  "sha256": "5d41402abc4b2a76b9719d911017c592a1b2c3d4e5f60718293a4b5c6d7e8f90",
  "dst_ip": "203.0.113.55",
  "url": "http://cdn.example.org/update/loader.bin",
  "cve": "CVE-2021-44228",
  "severity": "high"
}`
    }
  ],

  /* Keyed by lower-cased indicator. Shape mirrors the API's `sources` array. */
  intel: {
    "203.0.113.10": [
      {
        provider: "abuseipdb", label: "AbuseIPDB", status: "ok",
        facts: { abuse_confidence: 96, total_reports_90d: 412, distinct_reporters: 88, isp: "Sample Hosting BV", usage_type: "Data Center/Web Hosting", country: "NL", is_tor: false, top_categories: ["Port Scan", "Hacking", "Brute-Force"] },
        tags: ["Port Scan", "Brute-Force"],
        signals: [{ key: "abuseipdb", value: 0.96, rationale: "96% abuse confidence from 412 reports by 88 reporters in the last 90 days" }],
        relations: []
      },
      {
        provider: "threatfox", label: "ThreatFox (abuse.ch)", status: "ok",
        facts: { matches: 3, malware_families: ["SampleBot"], threat_types: ["botnet_cc"], confidence_level: 100, first_seen: "2026-08-29" },
        tags: ["botnet_cc", "sample-data"], malware_families: ["SampleBot"], attack_ids: ["T1071"],
        signals: [{ key: "threatfox", value: 1.0, rationale: "listed as active botnet_cc infrastructure for SampleBot (abuse.ch confidence 100%)" }],
        relations: [{ target: "SampleBot", target_type: "malware", relation: "attributed_to", confidence: 0.9 },
                    { target: "cdn.example.org", target_type: "domain", relation: "resolves_to", confidence: 0.7 }]
      },
      {
        provider: "greynoise", label: "GreyNoise", status: "ok",
        facts: { classification: "malicious", noise: true, riot: false, actor: "unknown", last_seen: "2026-09-17" },
        tags: ["greynoise:malicious", "mass-scanner"],
        signals: [{ key: "greynoise", value: 0.85, rationale: "GreyNoise observed this IP conducting malicious mass scanning" }],
        relations: []
      },
      {
        provider: "local_blocklist", label: "Local historical feeds", status: "ok",
        facts: { feed_hits: 2, feeds: ["feodo-tracker", "sample-offline"], malware_families: ["SampleBot C2"], first_seen: "2026-08-29" },
        tags: ["feed:feodo-tracker"], malware_families: ["SampleBot C2"], attack_ids: ["T1071"],
        signals: [{ key: "local_blocklist", value: 0.95, rationale: "present in offline feed(s): feodo-tracker, sample-offline — SampleBot C2" }],
        relations: [{ target: "SampleBot C2", target_type: "malware", relation: "attributed_to", confidence: 0.9 }]
      },
      {
        provider: "geoip", label: "MaxMind GeoLite2 (offline)", status: "ok",
        facts: { country: "NL", country_name: "Netherlands", city: "Amsterdam", asn: 200019, as_org: "Sample Hosting BV" },
        tags: ["elevated-asn"],
        signals: [{ key: "geoip", value: 0.4, rationale: "AS200019 — bulletproof-reputation hosting (sample dataset)" }],
        relations: [{ target: "AS200019", target_type: "asn", relation: "announced_by", confidence: 0.6 },
                    { target: "NL", target_type: "country", relation: "located_in", confidence: 0.5 }]
      },
      { provider: "urlhaus", label: "URLhaus (abuse.ch)", status: "clean", facts: { url_count: 0 }, signals: [{ key: "urlhaus", value: 0, rationale: "not listed on URLhaus" }], relations: [] },
      { provider: "otx", label: "AlienVault OTX", status: "ok",
        facts: { pulse_count: 9, pulse_names: ["SampleBot infrastructure — Sept 2026", "Mass RDP scanning wave"], malware_families: ["SampleBot"], adversaries: [], attack_ids: ["T1071", "T1110"] },
        tags: ["sample-campaign"], malware_families: ["SampleBot"], attack_ids: ["T1071", "T1110"],
        signals: [{ key: "otx", value: 0.87, rationale: "referenced in 9 OTX pulse(s); families: SampleBot" }],
        relations: [{ target: "SampleBot infrastructure — Sept 2026", target_type: "pulse", relation: "reported_in", confidence: 0.4 }] }
    ],

    "198.51.100.42": [
      { provider: "abuseipdb", label: "AbuseIPDB", status: "ok",
        facts: { abuse_confidence: 62, total_reports_90d: 37, distinct_reporters: 9, isp: "Sample Broadband", usage_type: "Fixed Line ISP", country: "DE", is_tor: false, top_categories: ["SSH", "Brute-Force"] },
        tags: ["SSH", "Brute-Force"],
        signals: [{ key: "abuseipdb", value: 0.58, rationale: "62% abuse confidence from 37 reports by 9 reporters in the last 90 days" }], relations: [] },
      { provider: "local_blocklist", label: "Local historical feeds", status: "ok",
        facts: { feed_hits: 1, feeds: ["sample-offline"], malware_families: ["SampleLoader"] },
        tags: ["feed:sample-offline"], malware_families: ["SampleLoader"],
        signals: [{ key: "local_blocklist", value: 0.8, rationale: "present in offline feed(s): sample-offline — SampleLoader" }],
        relations: [{ target: "SampleLoader", target_type: "malware", relation: "attributed_to", confidence: 0.9 }] },
      { provider: "greynoise", label: "GreyNoise", status: "ok",
        facts: { classification: "suspicious", noise: true, riot: false, actor: "unknown" },
        tags: ["greynoise:suspicious", "mass-scanner"],
        signals: [{ key: "greynoise", value: 0.55, rationale: "GreyNoise observed suspicious mass scanning from this IP" }], relations: [] },
      { provider: "geoip", label: "MaxMind GeoLite2 (offline)", status: "ok",
        facts: { country: "DE", country_name: "Germany", city: "Frankfurt", asn: 24940, as_org: "Sample Telecom" },
        signals: [{ key: "geoip", value: 0, rationale: "hosted in Germany on Sample Telecom" }],
        relations: [{ target: "AS24940", target_type: "asn", relation: "announced_by", confidence: 0.6 }] },
      { provider: "otx", label: "AlienVault OTX", status: "clean", facts: { pulse_count: 0 }, signals: [{ key: "otx", value: 0, rationale: "no OTX pulses reference this indicator" }], relations: [] },
      { provider: "threatfox", label: "ThreatFox (abuse.ch)", status: "clean", facts: { matches: 0 }, signals: [{ key: "threatfox", value: 0, rationale: "no ThreatFox IOC match" }], relations: [] },
      { provider: "urlhaus", label: "URLhaus (abuse.ch)", status: "clean", facts: {}, signals: [{ key: "urlhaus", value: 0, rationale: "not listed on URLhaus" }], relations: [] }
    ],

    "203.0.113.200": [
      { provider: "greynoise", label: "GreyNoise", status: "ok",
        facts: { classification: "benign", noise: true, riot: false, actor: "Sample Research Scanner", last_seen: "2026-09-18" },
        tags: ["greynoise:benign", "mass-scanner"],
        signals: [{ key: "greynoise", value: 0.05, rationale: "internet background noise — known scanner (Sample Research Scanner)" }], relations: [] },
      { provider: "abuseipdb", label: "AbuseIPDB", status: "ok",
        facts: { abuse_confidence: 41, total_reports_90d: 120, distinct_reporters: 34, isp: "Sample Research Labs", usage_type: "Data Center/Web Hosting", country: "US", top_categories: ["Port Scan"] },
        tags: ["Port Scan"],
        signals: [{ key: "abuseipdb", value: 0.41, rationale: "41% abuse confidence from 120 reports by 34 reporters in the last 90 days" }], relations: [] },
      { provider: "geoip", label: "MaxMind GeoLite2 (offline)", status: "ok",
        facts: { country: "US", country_name: "United States", city: "Ann Arbor", asn: 237, as_org: "Sample Research Labs" },
        signals: [{ key: "geoip", value: 0, rationale: "hosted in United States on Sample Research Labs" }],
        relations: [{ target: "AS237", target_type: "asn", relation: "announced_by", confidence: 0.6 }] },
      { provider: "otx", label: "AlienVault OTX", status: "ok",
        facts: { pulse_count: 2, pulse_names: ["Academic scanning infrastructure"], malware_families: [] },
        signals: [{ key: "otx", value: 0.3, rationale: "referenced in 2 OTX pulse(s)" }], relations: [] },
      { provider: "threatfox", label: "ThreatFox (abuse.ch)", status: "clean", facts: { matches: 0 }, signals: [{ key: "threatfox", value: 0, rationale: "no ThreatFox IOC match" }], relations: [] },
      { provider: "local_blocklist", label: "Local historical feeds", status: "clean", facts: { feed_hits: 0 }, signals: [{ key: "local_blocklist", value: 0, rationale: "no match in local historical feeds" }], relations: [] }
    ],

    "203.0.113.55": [
      { provider: "threatfox", label: "ThreatFox (abuse.ch)", status: "ok",
        facts: { matches: 1, malware_families: ["SampleBot"], threat_types: ["botnet_cc"], confidence_level: 90 },
        tags: ["botnet_cc"], malware_families: ["SampleBot"], attack_ids: ["T1071"],
        signals: [{ key: "threatfox", value: 0.9, rationale: "listed as active botnet_cc infrastructure for SampleBot (abuse.ch confidence 90%)" }],
        relations: [{ target: "SampleBot", target_type: "malware", relation: "attributed_to", confidence: 0.9 },
                    { target: "203.0.113.10", target_type: "ip", relation: "shares_campaign", confidence: 0.75 }] },
      { provider: "local_blocklist", label: "Local historical feeds", status: "ok",
        facts: { feed_hits: 1, feeds: ["sample-offline"], malware_families: ["SampleBot C2"] },
        tags: ["feed:sample-offline"], malware_families: ["SampleBot C2"], attack_ids: ["T1071"],
        signals: [{ key: "local_blocklist", value: 0.9, rationale: "present in offline feed(s): sample-offline — SampleBot C2" }], relations: [] },
      { provider: "abuseipdb", label: "AbuseIPDB", status: "ok",
        facts: { abuse_confidence: 74, total_reports_90d: 88, distinct_reporters: 21, isp: "Sample Hosting BV", country: "NL", top_categories: ["Hacking", "Web App Attack"] },
        tags: ["Hacking", "Web App Attack"],
        signals: [{ key: "abuseipdb", value: 0.74, rationale: "74% abuse confidence from 88 reports by 21 reporters in the last 90 days" }], relations: [] },
      { provider: "geoip", label: "MaxMind GeoLite2 (offline)", status: "ok",
        facts: { country: "NL", country_name: "Netherlands", asn: 200019, as_org: "Sample Hosting BV" },
        tags: ["elevated-asn"],
        signals: [{ key: "geoip", value: 0.4, rationale: "AS200019 — bulletproof-reputation hosting (sample dataset)" }],
        relations: [{ target: "AS200019", target_type: "asn", relation: "announced_by", confidence: 0.6 }] },
      { provider: "otx", label: "AlienVault OTX", status: "clean", facts: { pulse_count: 0 }, signals: [{ key: "otx", value: 0, rationale: "no OTX pulses reference this indicator" }], relations: [] },
      { provider: "urlhaus", label: "URLhaus (abuse.ch)", status: "clean", facts: {}, signals: [{ key: "urlhaus", value: 0, rationale: "not listed on URLhaus" }], relations: [] }
    ],

    "192.0.2.77": [
      { provider: "abuseipdb", label: "AbuseIPDB", status: "ok",
        facts: { abuse_confidence: 55, total_reports_90d: 24, distinct_reporters: 6, isp: "Sample Mail Relay", usage_type: "Data Center/Web Hosting", country: "US", top_categories: ["Email Spam", "Phishing"] },
        tags: ["Email Spam", "Phishing"],
        signals: [{ key: "abuseipdb", value: 0.48, rationale: "55% abuse confidence from 24 reports by 6 reporters in the last 90 days" }], relations: [] },
      { provider: "local_blocklist", label: "Local historical feeds", status: "ok",
        facts: { feed_hits: 1, feeds: ["sample-offline"], malware_families: ["SampleStealer"] },
        tags: ["feed:sample-offline"], malware_families: ["SampleStealer"],
        signals: [{ key: "local_blocklist", value: 0.8, rationale: "present in offline feed(s): sample-offline — SampleStealer" }], relations: [] },
      { provider: "otx", label: "AlienVault OTX", status: "ok",
        facts: { pulse_count: 4, pulse_names: ["Credential phishing relay cluster"], malware_families: [], attack_ids: ["T1566"] },
        tags: ["phishing"], attack_ids: ["T1566"],
        signals: [{ key: "otx", value: 0.62, rationale: "referenced in 4 OTX pulse(s)" }],
        relations: [{ target: "secure-login.example.com", target_type: "domain", relation: "hosts", confidence: 0.7 }] },
      { provider: "geoip", label: "MaxMind GeoLite2 (offline)", status: "ok",
        facts: { country: "US", country_name: "United States", asn: 14061, as_org: "Sample Cloud" },
        tags: ["elevated-asn"],
        signals: [{ key: "geoip", value: 0.4, rationale: "AS14061 — frequent abuse origin (sample dataset)" }],
        relations: [{ target: "AS14061", target_type: "asn", relation: "announced_by", confidence: 0.6 }] },
      { provider: "threatfox", label: "ThreatFox (abuse.ch)", status: "clean", facts: { matches: 0 }, signals: [{ key: "threatfox", value: 0, rationale: "no ThreatFox IOC match" }], relations: [] },
      { provider: "greynoise", label: "GreyNoise", status: "clean", facts: { classification: "unseen", noise: false }, signals: [{ key: "greynoise", value: 0.35, rationale: "not seen scanning the internet — consistent with targeted activity" }], relations: [] }
    ],

    "secure-login.example.com": [
      { provider: "urlhaus", label: "URLhaus (abuse.ch)", status: "ok",
        facts: { url_count: 6, blacklists: { spamhaus_dbl: "abused_legit_malware" }, first_seen: "2026-09-12" },
        tags: ["phishing", "credential-harvest"], malware_families: [], attack_ids: ["T1566.002"],
        signals: [{ key: "urlhaus", value: 0.9, rationale: "listed on URLhaus as an ONLINE malware distribution point" }],
        relations: [{ target: "https://secure-login.example.com/owa/session?id=8812", target_type: "url", relation: "hosts", confidence: 0.8 },
                    { target: "192.0.2.77", target_type: "ip", relation: "resolves_to", confidence: 0.8 }] },
      { provider: "otx", label: "AlienVault OTX", status: "ok",
        facts: { pulse_count: 7, pulse_names: ["OWA credential phishing kit", "Sample phishing wave — Sept"], malware_families: ["SamplePhishKit"], attack_ids: ["T1566.002"] },
        tags: ["phishing"], malware_families: ["SamplePhishKit"], attack_ids: ["T1566.002"],
        signals: [{ key: "otx", value: 0.82, rationale: "referenced in 7 OTX pulse(s); families: SamplePhishKit" }],
        relations: [{ target: "SamplePhishKit", target_type: "malware", relation: "attributed_to", confidence: 0.7 }] },
      { provider: "threatfox", label: "ThreatFox (abuse.ch)", status: "clean", facts: { matches: 0 }, signals: [{ key: "threatfox", value: 0, rationale: "no ThreatFox IOC match" }], relations: [] },
      { provider: "local_blocklist", label: "Local historical feeds", status: "clean", facts: { feed_hits: 0 }, signals: [{ key: "local_blocklist", value: 0, rationale: "no match in local historical feeds" }], relations: [] }
    ],

    "https://secure-login.example.com/owa/session?id=8812": [
      { provider: "urlhaus", label: "URLhaus (abuse.ch)", status: "ok",
        facts: { url_status: "online", threat: "phishing", date_added: "2026-09-12", reporter: "sample_reporter" },
        tags: ["phishing", "owa"], attack_ids: ["T1566.002"],
        signals: [{ key: "urlhaus", value: 0.95, rationale: "listed on URLhaus as an ONLINE malware distribution point" }],
        relations: [{ target: "secure-login.example.com", target_type: "domain", relation: "hosted_on", confidence: 0.8 }] },
      { provider: "otx", label: "AlienVault OTX", status: "ok",
        facts: { pulse_count: 5, malware_families: ["SamplePhishKit"], attack_ids: ["T1566.002"] },
        malware_families: ["SamplePhishKit"], attack_ids: ["T1566.002"], tags: ["credential-harvest"],
        signals: [{ key: "otx", value: 0.75, rationale: "referenced in 5 OTX pulse(s); families: SamplePhishKit" }], relations: [] },
      { provider: "threatfox", label: "ThreatFox (abuse.ch)", status: "clean", facts: { matches: 0 }, signals: [{ key: "threatfox", value: 0, rationale: "no ThreatFox IOC match" }], relations: [] },
      { provider: "local_blocklist", label: "Local historical feeds", status: "clean", facts: { feed_hits: 0 }, signals: [{ key: "local_blocklist", value: 0, rationale: "no match in local historical feeds" }], relations: [] }
    ],

    "5d41402abc4b2a76b9719d911017c592a1b2c3d4e5f60718293a4b5c6d7e8f90": [
      { provider: "urlhaus", label: "URLhaus (abuse.ch)", status: "ok",
        facts: { file_type: "exe", file_size: 486912, signature: "SampleLoader", first_seen: "2026-09-10", url_count: 3 },
        tags: ["loader"], malware_families: ["SampleLoader"], attack_ids: ["T1105"],
        signals: [{ key: "urlhaus", value: 0.95, rationale: "listed on URLhaus as an ONLINE malware distribution point (SampleLoader)" }],
        relations: [{ target: "http://cdn.example.org/update/loader.bin", target_type: "url", relation: "distributed_via", confidence: 0.8 },
                    { target: "SampleLoader", target_type: "malware", relation: "attributed_to", confidence: 0.85 }] },
      { provider: "threatfox", label: "ThreatFox (abuse.ch)", status: "ok",
        facts: { matches: 2, malware_families: ["SampleLoader"], threat_types: ["payload"], confidence_level: 95 },
        tags: ["payload"], malware_families: ["SampleLoader"],
        signals: [{ key: "threatfox", value: 0.95, rationale: "listed as active payload infrastructure for SampleLoader (abuse.ch confidence 95%)" }], relations: [] },
      { provider: "otx", label: "AlienVault OTX", status: "ok",
        facts: { pulse_count: 11, malware_families: ["SampleLoader"], attack_ids: ["T1105", "T1071"], hash_algorithm: "sha256" },
        malware_families: ["SampleLoader"], attack_ids: ["T1105", "T1071"], tags: ["loader", "sample-campaign"],
        signals: [{ key: "otx", value: 0.92, rationale: "referenced in 11 OTX pulse(s); families: SampleLoader" }], relations: [] },
      { provider: "local_blocklist", label: "Local historical feeds", status: "clean", facts: { feed_hits: 0 }, signals: [{ key: "local_blocklist", value: 0, rationale: "no match in local historical feeds" }], relations: [] }
    ],

    "http://cdn.example.org/update/loader.bin": [
      { provider: "urlhaus", label: "URLhaus (abuse.ch)", status: "ok",
        facts: { url_status: "online", threat: "malware_download", date_added: "2026-09-10" },
        tags: ["malware_download"], malware_families: ["SampleLoader"], attack_ids: ["T1105"],
        signals: [{ key: "urlhaus", value: 0.95, rationale: "listed on URLhaus as an ONLINE malware distribution point (SampleLoader)" }],
        relations: [{ target: "cdn.example.org", target_type: "domain", relation: "hosted_on", confidence: 0.8 },
                    { target: "5d41402abc4b2a76b9719d911017c592a1b2c3d4e5f60718293a4b5c6d7e8f90", target_type: "hash", relation: "drops_payload", confidence: 0.85 }] },
      { provider: "otx", label: "AlienVault OTX", status: "ok",
        facts: { pulse_count: 6, malware_families: ["SampleLoader"] },
        malware_families: ["SampleLoader"], attack_ids: ["T1105"], tags: ["loader"],
        signals: [{ key: "otx", value: 0.78, rationale: "referenced in 6 OTX pulse(s); families: SampleLoader" }], relations: [] },
      { provider: "threatfox", label: "ThreatFox (abuse.ch)", status: "clean", facts: { matches: 0 }, signals: [{ key: "threatfox", value: 0, rationale: "no ThreatFox IOC match" }], relations: [] },
      { provider: "local_blocklist", label: "Local historical feeds", status: "clean", facts: { feed_hits: 0 }, signals: [{ key: "local_blocklist", value: 0, rationale: "no match in local historical feeds" }], relations: [] }
    ],

    "cdn.example.org": [
      { provider: "urlhaus", label: "URLhaus (abuse.ch)", status: "ok",
        facts: { url_count: 3, first_seen: "2026-09-10" },
        tags: ["malware_download"], malware_families: ["SampleLoader"], attack_ids: ["T1105"],
        signals: [{ key: "urlhaus", value: 0.85, rationale: "listed on URLhaus as a historic malware distribution point (SampleLoader)" }],
        relations: [{ target: "203.0.113.10", target_type: "ip", relation: "resolves_to", confidence: 0.75 }] },
      { provider: "otx", label: "AlienVault OTX", status: "ok",
        facts: { pulse_count: 3, malware_families: ["SampleLoader"] },
        malware_families: ["SampleLoader"], attack_ids: ["T1105"],
        signals: [{ key: "otx", value: 0.55, rationale: "referenced in 3 OTX pulse(s); families: SampleLoader" }], relations: [] },
      { provider: "threatfox", label: "ThreatFox (abuse.ch)", status: "clean", facts: { matches: 0 }, signals: [{ key: "threatfox", value: 0, rationale: "no ThreatFox IOC match" }], relations: [] },
      { provider: "local_blocklist", label: "Local historical feeds", status: "clean", facts: { feed_hits: 0 }, signals: [{ key: "local_blocklist", value: 0, rationale: "no match in local historical feeds" }], relations: [] }
    ],

    "it-helpdesk@secure-login.example.com": [
      { provider: "otx", label: "AlienVault OTX", status: "ok",
        facts: { pulse_count: 3, malware_families: ["SamplePhishKit"], attack_ids: ["T1566"] },
        malware_families: ["SamplePhishKit"], attack_ids: ["T1566"], tags: ["phishing"],
        signals: [{ key: "otx", value: 0.6, rationale: "referenced in 3 OTX pulse(s); families: SamplePhishKit" }],
        relations: [{ target: "secure-login.example.com", target_type: "domain", relation: "sender_domain", confidence: 0.8 }] }
    ],

    "cve-2021-44228": [
      { provider: "nvd", label: "NVD (offline)", status: "ok",
        facts: { in_local_nvd: true, cvss_score: 10.0, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", severity: "CRITICAL", published: "2021-12-10", known_exploited: true, description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints (Log4Shell)." },
        tags: ["cvss:CRITICAL"], attack_ids: ["T1190"],
        signals: [{ key: "otx", value: 1.0, rationale: "CVSS 10.0 (CRITICAL) — known exploited in the wild" }],
        relations: [{ target: "CVE-2021-44228", target_type: "cve", relation: "exploits", confidence: 0.8 }] }
    ]
  }
};
