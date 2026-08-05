export type Severity = "safe" | "caution" | "danger" | "info";
export type Verdict = "safe" | "caution" | "danger" | "not-url";

export interface SafetyCheck {
  id: string;
  label: string;
  severity: Severity;
  passed: boolean;
  detail: string;
}

export interface SafetyReport {
  verdict: Verdict;
  url: URL | null;
  rawValue: string;
  checks: SafetyCheck[];
  tweetfeedMatch?: {
    isMalicious: boolean;
    source?: string;
    tags?: string[];
    tweetUrl?: string;
    date?: string;
  };
}

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in",
  "shorte.st", "adf.ly", "bl.ink", "snip.ly", "su.pr", "trib.al", "qr.ae",
]);

const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "work",
  "click", "country", "kim", "loan", "men", "gdn", "racing", "review",
]);

const BRAND_KEYWORDS = [
  "paypal", "apple", "microsoft", "google", "amazon", "facebook", "instagram",
  "netflix", "bank", "chase", "wellsfargo", "secure", "login", "verify",
  "account", "support", "appleid", "icloud",
];

function isIp(host: string) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
  if (host.startsWith("[") && host.endsWith("]")) return true;
  return false;
}

function hasMixedScript(host: string): boolean {
  const latin = /[a-zA-Z]/.test(host);
  const nonLatin = /[^\u0000-\u007F]/.test(host);
  return latin && nonLatin;
}

function getRegistrableDomain(host: string): string {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  return parts.slice(-2).join(".");
}

// Target API Base URL (Our local TweetFeed backend server or direct TweetFeed API)
const API_BASE_URL = typeof window !== "undefined" && (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")
  ? "http://localhost:8000"
  : "https://api.tweetfeed.live";

export function analyzeUrlSync(rawValue: string): SafetyReport {
  const trimmed = rawValue.trim();
  const checks: SafetyCheck[] = [];

  if (/^javascript:/i.test(trimmed)) {
    return {
      verdict: "danger",
      url: null,
      rawValue: trimmed,
      checks: [{
        id: "scheme-js",
        label: "JavaScript URI",
        severity: "danger",
        passed: false,
        detail: "This QR code runs JavaScript directly. Do not open.",
      }],
    };
  }
  if (/^data:/i.test(trimmed)) {
    return {
      verdict: "danger",
      url: null,
      rawValue: trimmed,
      checks: [{
        id: "scheme-data",
        label: "Data URI",
        severity: "danger",
        passed: false,
        detail: "Embeds inline content. Do not open.",
      }],
    };
  }

  let url: URL | null = null;
  try {
    const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    url = new URL(candidate);
  } catch {
    return { verdict: "not-url", url: null, rawValue: trimmed, checks: [] };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { verdict: "not-url", url: null, rawValue: trimmed, checks: [] };
  }

  const host = url.hostname;

  // HTTPS Check
  checks.push({
    id: "https",
    label: "Uses HTTPS",
    severity: url.protocol === "https:" ? "safe" : "caution",
    passed: url.protocol === "https:",
    detail: url.protocol === "https:"
      ? "Connection is encrypted."
      : "Plain HTTP — traffic isn't encrypted.",
  });

  // IP check
  const ip = isIp(host);
  checks.push({
    id: "ip",
    label: "Domain name (not raw IP)",
    severity: ip ? "danger" : "safe",
    passed: !ip,
    detail: ip ? "Points directly to an IP address." : "Uses a normal domain name.",
  });

  // Shortener check
  const shortened = SHORTENERS.has(host.toLowerCase());
  checks.push({
    id: "shortener",
    label: "Not a URL shortener",
    severity: shortened ? "caution" : "safe",
    passed: !shortened,
    detail: shortened ? `${host} is a URL shortener.` : "Destination is a direct host.",
  });

  // Suspicious TLD
  const tld = host.split(".").pop()?.toLowerCase() ?? "";
  if (SUSPICIOUS_TLDS.has(tld)) {
    checks.push({
      id: "tld",
      label: "Top-level domain review",
      severity: "caution",
      passed: false,
      detail: `.${tld} is commonly registered for spam or phishing.`,
    });
  }

  const hasDanger = checks.some((c) => !c.passed && c.severity === "danger");
  const hasCaution = checks.some((c) => !c.passed && c.severity === "caution");
  const verdict: Verdict = hasDanger ? "danger" : hasCaution ? "caution" : "safe";

  return { verdict, url, rawValue: trimmed, checks };
}

// Async TweetFeed API Checker
export async function analyzeUrlAsync(rawValue: string): Promise<SafetyReport> {
  const report = analyzeUrlSync(rawValue);
  if (!report.url) return report;

  const targetHost = report.url.hostname.toLowerCase();

  try {
    let matchFound = false;
    let sourceHandle = "@OSINT";
    let threatTags: string[] = ["#phishing"];
    let tweetLink = "";
    let dateStr = "Recent";

    // 1. Try Local TweetFeed API server first
    try {
      const res = await fetch(`${API_BASE_URL}/api/check?query=${encodeURIComponent(targetHost)}`);
      if (res.ok) {
        const data = await res.json();
        if (data.status === "FLAGGED_MALICIOUS") {
          matchFound = true;
          const dt = data.threat_details || {};
          sourceHandle = dt.source || "@OSINT";
          threatTags = dt.tags || ["#phishing"];
          tweetLink = dt.tweet || `https://x.com/search?q=${encodeURIComponent(targetHost)}`;
          dateStr = dt.date || "Recent";
        }
      }
    } catch (err) {
      // 2. Fallback direct to TweetFeed IOC API
      const directRes = await fetch(`https://api.tweetfeed.live/v1/ioc?value=${encodeURIComponent(targetHost)}`);
      if (directRes.ok) {
        const tf = await directRes.json();
        if (tf.found && tf.records && tf.records.length > 0) {
          matchFound = true;
          const rec = tf.records[0];
          sourceHandle = "@" + (rec.users ? rec.users[0] : "OSINT");
          threatTags = rec.tags || ["#phishing"];
          tweetLink = rec.tweets ? rec.tweets[0] : `https://x.com/search?q=${encodeURIComponent(targetHost)}`;
          dateStr = rec.first_seen || "365d Window";
        }
      }
    }

    if (matchFound) {
      report.verdict = "danger";
      report.tweetfeedMatch = {
        isMalicious: true,
        source: sourceHandle,
        tags: threatTags,
        tweetUrl: tweetLink,
        date: dateStr,
      };

      report.checks.unshift({
        id: "tweetfeed-intel",
        label: "Flagged by TweetFeed Threat Intelligence",
        severity: "danger",
        passed: false,
        detail: `Reported as malicious by infosec researcher ${sourceHandle} on X/Twitter. Threat tags: ${threatTags.join(" ")}`,
      });
    }
  } catch (err) {
    console.error("TweetFeed API check error:", err);
  }

  return report;
}