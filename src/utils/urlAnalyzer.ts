/**
 * ScamLens Local Structural URL Analyzer
 * Analyzes syntax, structure, protocols, and deceptive patterns strictly locally
 * without opening the destination or requesting remote network resources.
 */

import { UrlAnalysisResult, UrlFlag, UrlRiskLevel } from '../types/analyzer';

// High-risk and frequently abused TLDs in disposable phishing/scam campaigns
const HIGH_RISK_TLDS = [
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'click', 'work',
  'icu', 'cam', 'kim', 'vip', 'fit', 'monster', 'rest', 'surf', 'gdn', 'cfd', 'sbs'
];

// Known multi-part public suffixes (e.g., .co.in, .ac.in, .gov.in, .co.uk, .bank.in)
const KNOWN_MULTI_PART_TLDS = new Set([
  'co.in', 'ac.in', 'edu.in', 'gov.in', 'res.in', 'net.in', 'org.in', 'nic.in', 'bank.in',
  'co.uk', 'ac.uk', 'gov.uk', 'org.uk', 'net.uk', 'ltd.uk', 'plc.uk',
  'com.au', 'edu.au', 'gov.au', 'org.au', 'net.au',
  'co.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'co.nz', 'ac.nz', 'govt.nz', 'org.nz',
  'com.br', 'gov.br', 'edu.br',
  'edu.sg', 'gov.sg', 'com.sg',
  'co.za', 'gov.za', 'ac.za', 'edu.za',
  'gc.ca', 'qc.ca'
]);

// Verified academic and governmental registries
const INSTITUTIONAL_TLDS = new Set([
  'ac.in', 'edu.in', 'gov.in', 'res.in', 'nic.in',
  'edu', 'gov', 'mil',
  'ac.uk', 'gov.uk',
  'edu.au', 'gov.au',
  'ac.nz', 'govt.nz',
  'edu.sg', 'gov.sg',
  'gov.br', 'edu.br',
  'ac.za', 'gov.za', 'edu.za'
]);

// Known URL Shortener domains
const SHORTENER_DOMAINS = [
  'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'shorturl.at',
  'ow.ly', 'rebrand.ly', 'buff.ly', 'v.gd', 'bl.ink'
];

// Major brands frequently targeted by deceptive spoofing in student/banking fraud
// Supports explicit concatenated brand terms (hdfcbank, sbibank, icicibank, axisbank) and legitimate domain variants
const COMMONLY_SPOOFED_BRANDS: Array<{
  name: string;
  keyword: string;
  keywords: string[];
  officialSuffix: string;
  officialSuffixes: string[];
}> = [
  {
    name: 'HDFC Bank',
    keyword: 'hdfc',
    keywords: ['hdfc', 'hdfcbank'],
    officialSuffix: 'hdfcbank.com',
    officialSuffixes: ['hdfcbank.com'],
  },
  {
    name: 'State Bank of India',
    keyword: 'sbi',
    keywords: ['sbi', 'sbibank', 'onlinesbi'],
    officialSuffix: 'sbi.co.in',
    officialSuffixes: ['sbi.co.in', 'sbi.bank.in', 'bank.sbi', 'onlinesbi.sbi', 'onlinesbi.com'],
  },
  {
    name: 'ICICI Bank',
    keyword: 'icici',
    keywords: ['icici', 'icicibank'],
    officialSuffix: 'icicibank.com',
    officialSuffixes: ['icicibank.com'],
  },
  {
    name: 'Axis Bank',
    keyword: 'axis',
    keywords: ['axis', 'axisbank'],
    officialSuffix: 'axisbank.com',
    officialSuffixes: ['axisbank.com', 'axis.com'],
  },
  {
    name: 'Paytm',
    keyword: 'paytm',
    keywords: ['paytm', 'paytmbank'],
    officialSuffix: 'paytm.com',
    officialSuffixes: ['paytm.com', 'paytmbank.com'],
  },
  {
    name: 'PhonePe',
    keyword: 'phonepe',
    keywords: ['phonepe'],
    officialSuffix: 'phonepe.com',
    officialSuffixes: ['phonepe.com'],
  },
  {
    name: 'Google / GPay',
    keyword: 'google',
    keywords: ['google', 'gpay'],
    officialSuffix: 'google.com',
    officialSuffixes: ['google.com'],
  },
  {
    name: 'PayPal',
    keyword: 'paypal',
    keywords: ['paypal'],
    officialSuffix: 'paypal.com',
    officialSuffixes: ['paypal.com'],
  },
  {
    name: 'Apple',
    keyword: 'apple',
    keywords: ['apple'],
    officialSuffix: 'apple.com',
    officialSuffixes: ['apple.com'],
  },
  {
    name: 'Amazon',
    keyword: 'amazon',
    keywords: ['amazon'],
    officialSuffix: 'amazon.com',
    officialSuffixes: ['amazon.com'],
  },
  {
    name: 'Microsoft',
    keyword: 'microsoft',
    keywords: ['microsoft'],
    officialSuffix: 'microsoft.com',
    officialSuffixes: ['microsoft.com'],
  },
  {
    name: 'WhatsApp',
    keyword: 'whatsapp',
    keywords: ['whatsapp'],
    officialSuffix: 'whatsapp.com',
    officialSuffixes: ['whatsapp.com'],
  },
  {
    name: 'Telegram',
    keyword: 'telegram',
    keywords: ['telegram'],
    officialSuffix: 'telegram.org',
    officialSuffixes: ['telegram.org'],
  },
  {
    name: 'Netflix',
    keyword: 'netflix',
    keywords: ['netflix'],
    officialSuffix: 'netflix.com',
    officialSuffixes: ['netflix.com'],
  },
];

// Phishing and sensitive credential action keywords in URL paths/subdomains
const PHISHING_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'kyc', 'update', 'security',
  'account-confirm', 'confirm-identity', 'auth', 'checkpoint', 'aadhaar',
  'pan-card', 'claim-reward', 'refund-portal', 'wallet-connect', 'seed-phrase',
  'banking-online', 'otp-check', 'bill-recharge', 'urgent-action'
];

// Executable / malicious file extensions
const EXECUTABLE_EXTENSIONS = ['.apk', '.exe', '.scr', '.bat', '.cmd', '.msi', '.vbs', '.iso', '.ps1', '.jar'];

/**
 * Parses effective TLD, root domain, and subdomain levels supporting multi-part domains.
 */
export function parseDomainStructure(hostname: string): {
  effectiveTld: string;
  rootDomain: string;
  subdomain: string;
  subdomainLevels: number;
} {
  const parts = hostname.split('.');
  if (parts.length <= 1) {
    return { effectiveTld: '', rootDomain: hostname, subdomain: '', subdomainLevels: 0 };
  }

  // Check if the last two parts form a known multi-part TLD (e.g. co.in, ac.in)
  const lastTwo = parts.slice(-2).join('.');
  if (KNOWN_MULTI_PART_TLDS.has(lastTwo)) {
    const effectiveTld = lastTwo;
    const rootDomain = parts.length >= 3 ? parts.slice(-3).join('.') : hostname;
    const subdomainParts = parts.length > 3 ? parts.slice(0, -3) : [];
    const subdomain = subdomainParts.join('.');
    const subdomainLevels = subdomainParts.length;
    return { effectiveTld, rootDomain, subdomain, subdomainLevels };
  }

  const effectiveTld = parts[parts.length - 1];
  const rootDomain = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  const subdomainParts = parts.length > 2 ? parts.slice(0, -2) : [];
  const subdomain = subdomainParts.join('.');
  const subdomainLevels = subdomainParts.length;
  return { effectiveTld, rootDomain, subdomain, subdomainLevels };
}

/**
 * Validates domain and IP hostnames according to standard RFC web naming syntax.
 * Rejects hostnames containing invalid characters (e.g. repeated '=' or prohibited punctuation).
 */
export function isValidHostname(host: string): boolean {
  if (!host || host.length === 0) return false;

  // Direct IPv4
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    const octets = host.split('.').map(Number);
    return octets.every((o) => o >= 0 && o <= 255);
  }

  // IPv6
  if (/^\[[a-fA-F0-9:]+\]$/.test(host)) {
    return true;
  }

  // Localhost
  if (host === 'localhost') {
    return true;
  }

  // Standard web domain must contain at least one dot (e.g. google.com)
  if (!host.includes('.')) {
    return false;
  }

  const labels = host.split('.');
  if (labels.some((l) => !l || l.length > 63)) {
    return false;
  }

  // Labels must be alphanumeric, may have internal hyphens
  const labelRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/;
  if (!labels.every((l) => labelRegex.test(l))) {
    return false;
  }

  // TLD must be at least 2 characters alphabetic or punycode xn--
  const tld = labels[labels.length - 1];
  if (!/^[a-zA-Z]{2,}$/.test(tld) && !tld.startsWith('xn--')) {
    return false;
  }

  return true;
}

export function analyzeUrl(rawInput: string): UrlAnalysisResult {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new Error('Please enter a valid website URL to inspect.');
  }

  // Guard against control characters / non-printable characters
  if (/[\x00-\x1F\x7F]/.test(trimmed)) {
    throw new Error('Malformed URL: Input contains invalid control characters or non-printable bytes.');
  }

  // Guard against excessively long input
  if (trimmed.length > 4096) {
    throw new Error('URL input is excessively long (exceeds 4096 characters). Please verify the link.');
  }

  // 1. Safe Scheme Validation: Reject non-web schemes (e.g. javascript:, file:, data:, upi:)
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  let normalized = trimmed;

  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      throw new Error(
        `Unsupported URL scheme "${scheme}:". ScamLens only inspects standard web links (HTTP/HTTPS). It cannot analyze non-web schemes like ${scheme}:, javascript:, file:, or data:.`
      );
    }
  } else {
    // If no scheme was provided, default to https:// for safe normalization
    normalized = 'https://' + trimmed;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error('Malformed URL structure. Please provide a valid web domain or URL (e.g. google.com or https://example.ac.in).');
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!isValidHostname(hostname)) {
    throw new Error('Malformed URL: Destination hostname is invalid or contains prohibited characters. Please enter a valid domain (e.g., google.com or https://example.ac.in).');
  }

  const flags: UrlFlag[] = [];
  let riskScore = 0;

  const protocol = parsed.protocol.replace(':', '').toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const searchParams = parsed.search;

  // 2. Insecure HTTP Protocol Check
  // Note: HTTP means absence of TLS encryption, not definite proof of fraud
  if (protocol === 'http') {
    riskScore += 25;
    flags.push({
      id: 'flag_http',
      name: 'Insecure Transmission Protocol (HTTP)',
      severity: 'high',
      description: 'The URL uses unencrypted HTTP rather than modern HTTPS.',
      detail:
        'Authentic educational, banking, and student login portals strictly enforce HTTPS with TLS encryption. Unencrypted HTTP exposes credentials and form inputs to network interception. (Note: HTTP indicates lack of encryption, not confirmed maliciousness).',
    });
  }

  // 3. Raw IP Address as Hostname
  const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const isIpAddress = ipv4Regex.test(hostname) || (hostname.startsWith('[') && hostname.endsWith(']'));
  if (isIpAddress) {
    riskScore += 40;
    flags.push({
      id: 'flag_ip_address',
      name: 'Direct IP Address Hostname',
      severity: 'critical',
      description: 'The link points directly to a numeric IP address rather than a registered domain name.',
      detail:
        'Attackers frequently host phishing toolkits directly on raw cloud or VPS IP addresses to evade domain reputation blocklists and registrar identity checks.',
    });
  }

  // 4. Domain & Multi-part Suffix Decomposition
  const { effectiveTld, rootDomain, subdomain, subdomainLevels } = parseDomainStructure(hostname);

  // 5. Educational / Institutional Registry Signal
  if (INSTITUTIONAL_TLDS.has(effectiveTld)) {
    flags.push({
      id: 'flag_institutional_registry',
      name: `Accredited Institutional Suffix (.${effectiveTld})`,
      severity: 'info',
      description: `The domain uses the .${effectiveTld} registry, restricted to accredited academic or government organizations.`,
      detail:
        `Registries verify institutional credentials before issuing .${effectiveTld} domains. Note: always confirm that the specific subdomain belongs to your genuine institution.`,
    });
  }

  // 6. Suspicious / Abused Top-Level Domain
  // Suffix alone is a heuristic indicator, not definitive proof of fraud
  if (HIGH_RISK_TLDS.includes(effectiveTld)) {
    riskScore += 15;
    flags.push({
      id: 'flag_suspicious_tld',
      name: `Higher-Frequency Disposable TLD (.${effectiveTld})`,
      severity: 'warning',
      description: `The domain utilizes .${effectiveTld}, an extension statistically common in disposable spam and phishing campaigns due to low acquisition costs.`,
      detail:
        `While legitimate sites also use .${effectiveTld}, this suffix alone does not prove fraud. It is a heuristic risk indicator that warrants verifying the sender through independent channels.`,
    });
  }

  // 7. URL Shortener Concealment
  const isShortener = SHORTENER_DOMAINS.some(
    (shortener) => hostname === shortener || hostname.endsWith('.' + shortener)
  );
  if (isShortener) {
    riskScore += 25;
    flags.push({
      id: 'flag_shortener',
      name: 'Obfuscating URL Shortener',
      severity: 'warning',
      description: 'The link directs through an intermediate URL shortening service.',
      detail:
        'URL shorteners conceal the true destination server from the recipient until clicked. While frequently used for brevity, they are also commonly employed to hide credential harvesting forms or malicious payloads.',
    });
  }

  // 8. Brand Spoofing / Typosquatting / Subdomain Deception
  let isBrandSpoofed = false;
  for (const brand of COMMONLY_SPOOFED_BRANDS) {
    let matchedKeyword: string | null = null;
    let matchedRegex: RegExp | null = null;

    // Check all explicit brand variants against the hostname
    for (const kw of brand.keywords) {
      const regex = new RegExp(`(^|[.-])${kw}([.-]|$)`, 'i');
      if (regex.test(hostname)) {
        matchedKeyword = kw;
        matchedRegex = regex;
        break;
      }
    }

    if (matchedKeyword && matchedRegex) {
      // Precise official domain suffix matching to prevent false positives on genuine brand portals
      const isOfficial = brand.officialSuffixes.some((suffix) => {
        const s = suffix.toLowerCase();
        const normHost = hostname.toLowerCase();
        const normRoot = rootDomain.toLowerCase();
        return (
          normHost === s ||
          normHost.endsWith('.' + s) ||
          normRoot === s ||
          normRoot.endsWith('.' + s)
        );
      });

      if (!isOfficial) {
        isBrandSpoofed = true;
        const isBrandInSubdomain = Boolean(subdomain && matchedRegex.test(subdomain));
        if (isBrandInSubdomain) {
          riskScore += 35;
          flags.push({
            id: `flag_brand_spoof_subdomain_${brand.keyword}`,
            name: `Deceptive Subdomain Brand Spoofing (${brand.name})`,
            severity: 'critical',
            description: `The subdomain "${subdomain}" mimics ${brand.name}, but the true registered destination domain is "${rootDomain}".`,
            detail: `Attackers stack reputable brand names in subdomains (e.g. "${matchedKeyword}.co.in.scam-server.xyz") to mislead mobile users whose browser address bars truncate long hostnames.`,
          });
        } else {
          riskScore += 35;
          flags.push({
            id: `flag_brand_spoof_${brand.keyword}`,
            name: `Suspected Brand Typosquatting / Impersonation (${brand.name})`,
            severity: 'critical',
            description: `The host references "${matchedKeyword}" but the registered root domain (${rootDomain}) is not affiliated with the official ${brand.officialSuffixes[0]}.`,
            detail: `This matches deceptive domain lookalike patterns designed to trick students into believing they are visiting ${brand.name}.`,
          });
        }
        break;
      } else {
        // Officially verified endpoint for this brand; cannot be an impersonation
        break;
      }
    }
  }

  // 9. Non-Standard Network Port Inspection
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    riskScore += 25;
    flags.push({
      id: 'flag_unusual_port',
      name: `Unusual Network Port (:${parsed.port})`,
      severity: 'warning',
      description: `The URL explicitly connects via non-standard network port :${parsed.port}.`,
      detail:
        'Legitimate public banking, educational, and consumer web portals operate on standard web ports (80 HTTP / 443 HTTPS). Non-standard ports are frequently used to host temporary phishing kits or bypass network security filters.',
    });
  }

  // 10. Embedded Userinfo (@ Symbol Trick)
  if (rawInput.includes('@') || Boolean(parsed.username || parsed.password)) {
    riskScore += 35;
    flags.push({
      id: 'flag_userinfo_at',
      name: 'Deceptive Userinfo (@ Symbol Trick)',
      severity: 'critical',
      description: 'URL contains the "@" character inside the domain authority portion.',
      detail:
        'Browsers interpret text before the "@" as login credentials and navigate to the server specified AFTER the "@". For example, "http://google.com@evil-site.com" connects to evil-site.com.',
    });
  }

  // 11. Punycode / IDN Homograph Attack
  if (hostname.includes('xn--')) {
    riskScore += 30;
    flags.push({
      id: 'flag_punycode',
      name: 'Internationalized Domain Name (Punycode xn--)',
      severity: 'critical',
      description: 'The domain name contains Punycode encoded characters.',
      detail:
        'Attackers use lookalike Unicode characters (such as Cyrillic "а" instead of Latin "a") that encode as "xn--" to visually mimic trusted academic or banking domains.',
    });
  }

  // 12. Direct Executable / APK Download Payload
  const hasExecutablePath = EXECUTABLE_EXTENSIONS.some((ext) => pathname.endsWith(ext));
  if (hasExecutablePath) {
    riskScore += 35;
    flags.push({
      id: 'flag_executable_download',
      name: 'Direct Executable / APK Download Payload',
      severity: 'critical',
      description: 'The URL path points directly to an executable binary or Android package (.apk).',
      detail:
        'Opening this link triggers a direct application download. Sideloaded APKs distributed via chat links frequently steal OTPs or grant attackers remote control.',
    });
  }

  // 13. Phishing Keywords in Path or Subdomain
  // Accuracy fix: Do NOT penalize authentic/standard sites merely for having a login page.
  // Only penalize if accompanied by other risk signals (disposable TLD, HTTP, shortener, IP, brand spoofing, or 3+ clustered keywords).
  const matchedKeywords: string[] = [];
  for (const kw of PHISHING_KEYWORDS) {
    if (pathname.includes(kw) || hostname.includes(kw)) {
      matchedKeywords.push(kw);
    }
  }

  const hasCorroboratingRisk = isBrandSpoofed || isIpAddress || protocol === 'http' || isShortener || HIGH_RISK_TLDS.includes(effectiveTld) || subdomainLevels >= 3;

  if (matchedKeywords.length >= 3 || (matchedKeywords.length >= 1 && hasCorroboratingRisk)) {
    riskScore += 15;
    flags.push({
      id: 'flag_phishing_keywords',
      name: 'Sensitive Credential Action Keywords in Suspicious Context',
      severity: 'high',
      description: `URL path contains credential solicitation patterns: "${matchedKeywords.slice(0, 3).join('", "')}".`,
      detail:
        'Clustering words like login, verify, kyc, and otp on non-standard, unencrypted, or spoofed domains strongly correlates with fake credential harvesting forms.',
    });
  } else if (matchedKeywords.length >= 1) {
    // Single login/verify term on standard HTTPS domain: Informational check only (0 penalty points)
    flags.push({
      id: 'flag_phishing_keyword_info',
      name: 'Standard Account Action Keyword in URL',
      severity: 'info',
      description: `URL contains account action keyword "${matchedKeywords[0]}".`,
      detail: 'Standard authentication endpoint. Always verify you are on the authentic official domain before logging in.',
    });
  }

  // 14. Excessive Subdomain Stacking
  if (subdomainLevels >= 3 && !isIpAddress) {
    riskScore += 15;
    flags.push({
      id: 'flag_excessive_subdomains',
      name: 'Deep Multi-Level Subdomain Structure',
      severity: 'warning',
      description: `The URL contains ${subdomainLevels} levels of nested subdomains.`,
      detail:
        'Attackers frequently stack multiple subdomains (e.g. "secure.login.bank.portal.fakehost.net") to push the actual domain off-screen on mobile browsers.',
    });
  }

  // 15. Hyphenated Domain Clutter
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    riskScore += 15;
    flags.push({
      id: 'flag_excessive_hyphens',
      name: 'Multiple Hyphenated Domain Tokens',
      severity: 'warning',
      description: `Domain contains ${hyphenCount} hyphens, indicating artificial keyword-stuffing.`,
      detail:
        'Phishing domains frequently chain hyphens to simulate complex corporate infrastructure (e.g. "student-portal-support-verify-login.xyz").',
    });
  }

  // Cap score strictly at 100
  const finalRiskScore = Math.min(100, Math.max(0, riskScore));

  // Harmonized Verdicts (aligned with 0-24 SAFE, 25-59 RISKY, 60-100 SUSPICIOUS)
  let verdict: UrlRiskLevel = 'SAFE';
  if (finalRiskScore >= 60) {
    verdict = 'SUSPICIOUS';
  } else if (finalRiskScore >= 25) {
    verdict = 'RISKY';
  } else {
    verdict = 'SAFE';
  }

  // Separate actual warning indicators (warning, high, critical) from informational trust signals (info)
  const warningFlags = flags.filter((f) => f.severity !== 'info');
  const infoFlags = flags.filter((f) => f.severity === 'info');
  const warningCount = warningFlags.length;

  let summary = '';
  if (warningCount > 0) {
    summary = `Detected ${warningCount} structural warning indicator${warningCount > 1 ? 's' : ''} in the URL syntax.`;
  } else if (infoFlags.length > 0) {
    summary = `No structural warning signs detected. Found ${infoFlags.length} informational verification signal${infoFlags.length > 1 ? 's' : ''}.`;
  } else {
    summary = 'No structural warning signs or syntax anomalies detected. Link appears structurally standard.';
  }

  // Practical safety recommendations
  const recommendations: string[] = [];
  if (flags.some((f) => f.severity === 'critical')) {
    recommendations.push('Do NOT open this link or input any student ID, password, or bank details.');
    recommendations.push('If this link was received via SMS, WhatsApp, or Telegram, report and block the sender.');
  }
  if (isShortener) {
    recommendations.push('Avoid clicking shortened links from unknown senders. Inspect the unshortened destination first.');
  }
  if (isIpAddress) {
    recommendations.push('Legitimate student and university services never ask users to access raw IP addresses.');
  }
  if (protocol === 'http') {
    recommendations.push('Avoid submitting forms or logging into websites over unencrypted HTTP connections.');
  }
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    recommendations.push(`Be cautious of non-standard port connections (port ${parsed.port}). Legitimate web logins use default ports 80/443.`);
  }
  if (warningCount === 0) {
    recommendations.push('No critical structural red flags were detected in the URL syntax.');
    recommendations.push('Heuristic checks cannot establish live reputation or destination safety; always verify domain ownership independently.');
  }

  return {
    inputUrl: trimmed,
    normalizedUrl: parsed.href,
    isValid: true,
    verdict,
    riskScore: finalRiskScore,
    warningCount,
    summary,
    protocol,
    hostname,
    rootDomain,
    effectiveTld,
    pathname,
    searchParams,
    tld: effectiveTld,
    isIpAddress,
    flags,
    recommendations,
    analysisTimestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
  };
}
