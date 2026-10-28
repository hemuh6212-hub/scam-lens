/**
 * ScamLens Sandbox Website Scanner Engine
 * Safely fetches and inspects live websites in an isolated backend sandbox.
 * Enforces robust SSRF defenses: restricts private/internal/cloud-metadata networks (IPv4/IPv6),
 * validates allowed web protocols and ports, mitigates DNS rebinding via custom connection hooks,
 * enforces hop/scan timeouts, caps response size, and parses DOM forms/content safely.
 */

import dns from 'node:dns/promises';
import dnsCallback from 'node:dns';
import net from 'node:net';
import { Agent, buildConnector } from 'undici';
import * as cheerio from 'cheerio';
import { SandboxScanResult, UrlFlag, UrlRiskLevel } from '../types/analyzer';
import { analyzeMessage } from './messageAnalyzer';
import { isValidHostname, parseDomainStructure } from './urlAnalyzer';

/**
 * Parses IPv6 address string into an array of 8 16-bit unsigned integers.
 * Supports standard shorthand notation (::) and embedded IPv4-mapped / IPv4-compatible dotted quads.
 */
export function parseIPv6Words(ip: string): number[] | null {
  const zoneIndex = ip.indexOf('%');
  const clean = zoneIndex !== -1 ? ip.slice(0, zoneIndex) : ip;

  const parts = clean.split('::');
  if (parts.length > 2) return null; // multiple :: invalid

  const parseHalf = (str: string): number[] | null => {
    if (!str) return [];
    const tokens = str.split(':');
    const result: number[] = [];
    for (const token of tokens) {
      if (token.includes('.')) {
        // Embedded IPv4 dotted quad at the end of IPv6
        const octets = token.split('.').map(Number);
        if (octets.length !== 4 || octets.some((o) => isNaN(o) || o < 0 || o > 255)) return null;
        result.push((octets[0] << 8) | octets[1]);
        result.push((octets[2] << 8) | octets[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(token)) return null;
        result.push(parseInt(token, 16));
      }
    }
    return result;
  };

  if (parts.length === 1) {
    const words = parseHalf(parts[0]);
    return words && words.length === 8 ? words : null;
  }

  const left = parseHalf(parts[0]);
  const right = parseHalf(parts[1]);
  if (!left || !right) return null;
  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;
  return [...left, ...new Array(missing).fill(0), ...right];
}

/**
 * Checks if 4 IPv4 octets fall within any non-routable, private, loopback,
 * link-local, test, multicast, or reserved ranges (RFC 1918, 1122, 3927, 6598, 5737, etc.).
 */
export function isPrivateIPv4Octets(a: number, b: number, c: number, d: number): boolean {
  // 0.0.0.0/8 (Current network / "this host on this network" RFC 1122)
  if (a === 0) return true;
  // 10.0.0.0/8 (Private network RFC 1918)
  if (a === 10) return true;
  // 100.64.0.0/10 (Shared Address Space / CGNAT RFC 6598: 100.64.0.0 - 100.127.255.255)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8 (Loopback RFC 1122)
  if (a === 127) return true;
  // 169.254.0.0/16 (Link-Local / Cloud Metadata RFC 3927)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (Private network RFC 1918: 172.16.0.0 - 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24 (IETF Protocol Assignments RFC 6890)
  if (a === 192 && b === 0 && c === 0) return true;
  // 192.0.2.0/24 (TEST-NET-1 for documentation RFC 5737)
  if (a === 192 && b === 0 && c === 2) return true;
  // 192.88.99.0/24 (6to4 Relay Anycast RFC 7526)
  if (a === 192 && b === 88 && c === 99) return true;
  // 192.168.0.0/16 (Private network RFC 1918)
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15 (Benchmarking RFC 2544: 198.18.0.0 - 198.19.255.255)
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 198.51.100.0/24 (TEST-NET-2 RFC 5737)
  if (a === 198 && b === 51 && c === 100) return true;
  // 203.0.113.0/24 (TEST-NET-3 RFC 5737)
  if (a === 203 && b === 0 && c === 113) return true;
  // 224.0.0.0/4 (Multicast RFC 5771: 224.0.0.0 - 239.255.255.255)
  if (a >= 224 && a <= 239) return true;
  // 240.0.0.0/4 (Reserved / Broadcast RFC 1112: 240.0.0.0 - 255.255.255.255)
  if (a >= 240) return true;

  return false;
}

/**
 * Parses IPv4 address supporting all POSIX inet_aton representations:
 * - 4-part: a.b.c.d (each part 8-bit)
 * - 3-part: a.b.c (a, b 8-bit, c 16-bit)
 * - 2-part: a.b (a 8-bit, b 24-bit)
 * - 1-part: a (32-bit integer)
 * Each part can be decimal, hex (0x...), or octal (0...).
 */
export function parseIPv4Alternative(raw: string): [number, number, number, number] | null {
  if (!raw || typeof raw !== 'string') return null;
  const str = raw.trim();
  if (!str) return null;

  const parts = str.split('.');
  if (parts.length < 1 || parts.length > 4) return null;

  const parsedParts: number[] = [];
  for (const part of parts) {
    if (!part) return null;
    let val: number;
    if (/^0x[0-9a-fA-F]+$/i.test(part)) {
      val = parseInt(part, 16);
    } else if (/^0[0-7]+$/.test(part)) {
      val = parseInt(part, 8);
    } else if (/^[0-9]+$/.test(part)) {
      // If it starts with 0 and contains non-octal digits (e.g. 08, 09), it's invalid octal
      if (part.length > 1 && part.startsWith('0')) return null;
      val = parseInt(part, 10);
    } else {
      return null;
    }

    if (isNaN(val) || val < 0) return null;
    parsedParts.push(val);
  }

  let full32: number;
  if (parsedParts.length === 4) {
    if (parsedParts.some((p) => p > 255)) return null;
    return [parsedParts[0], parsedParts[1], parsedParts[2], parsedParts[3]];
  } else if (parsedParts.length === 3) {
    if (parsedParts[0] > 255 || parsedParts[1] > 255 || parsedParts[2] > 65535) return null;
    full32 = ((parsedParts[0] & 0xff) * 0x1000000) + ((parsedParts[1] & 0xff) * 0x10000) + parsedParts[2];
  } else if (parsedParts.length === 2) {
    if (parsedParts[0] > 255 || parsedParts[1] > 16777215) return null;
    full32 = ((parsedParts[0] & 0xff) * 0x1000000) + parsedParts[1];
  } else {
    // 1 part
    if (parsedParts[0] > 0xffffffff) return null;
    full32 = parsedParts[0];
  }

  const a = Math.floor(full32 / 0x1000000) & 0xff;
  const b = Math.floor(full32 / 0x10000) & 0xff;
  const c = Math.floor(full32 / 0x100) & 0xff;
  const d = full32 & 0xff;
  return [a, b, c, d];
}

/**
 * Validates whether an IP address belongs to private/internal/cloud-metadata networks (SSRF defense).
 * Supports standard IPv4, raw integer/hex/octal representations, and comprehensive IPv6 RFC classifications.
 */
export function isPrivateIp(rawIp: string): boolean {
  if (!rawIp || typeof rawIp !== 'string') return true;
  const ip = rawIp.trim().replace(/^\[|\]$/g, '');
  if (!ip) return true;

  // 1. Direct standard IPv4
  const ipType = net.isIP(ip);
  if (ipType === 4) {
    const octets = ip.split('.').map(Number);
    if (octets.length !== 4 || octets.some((o) => isNaN(o) || o < 0 || o > 255)) return true;
    return isPrivateIPv4Octets(octets[0], octets[1], octets[2], octets[3]);
  }

  // 2. Comprehensive IPv6
  if (ipType === 6) {
    const words = parseIPv6Words(ip);
    if (!words) return true; // Malformed IPv6 treated as unsafe

    // Unspecified ::/128
    if (words.every((w) => w === 0)) return true;
    // Loopback ::1/128
    if (words.slice(0, 7).every((w) => w === 0) && words[7] === 1) return true;

    // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::0:0/96)
    if (words.slice(0, 5).every((w) => w === 0) && (words[5] === 0xffff || words[5] === 0)) {
      const a = (words[6] >> 8) & 0xff;
      const b = words[6] & 0xff;
      const c = (words[7] >> 8) & 0xff;
      const d = words[7] & 0xff;
      return isPrivateIPv4Octets(a, b, c, d);
    }

    // NAT64 64:ff9b::/96
    if (words[0] === 0x0064 && words[1] === 0xff9b && words.slice(2, 6).every((w) => w === 0)) {
      const a = (words[6] >> 8) & 0xff;
      const b = words[6] & 0xff;
      const c = (words[7] >> 8) & 0xff;
      const d = words[7] & 0xff;
      return isPrivateIPv4Octets(a, b, c, d);
    }

    // 6to4 2002::/16 (embeds IPv4 in words 1 and 2)
    if (words[0] === 0x2002) {
      const a = (words[1] >> 8) & 0xff;
      const b = words[1] & 0xff;
      const c = (words[2] >> 8) & 0xff;
      const d = words[2] & 0xff;
      return isPrivateIPv4Octets(a, b, c, d);
    }

    // ULA fc00::/7 (fc00: to fdff:)
    if ((words[0] & 0xfe00) === 0xfc00) return true;
    // Link-local fe80::/10 (fe80: to febf:)
    if ((words[0] & 0xffc0) === 0xfe80) return true;
    // Site-local (deprecated) fec0::/10
    if ((words[0] & 0xffc0) === 0xfec0) return true;
    // Multicast ff00::/8
    if ((words[0] & 0xff00) === 0xff00) return true;
    // Discard 100::/64
    if (words[0] === 0x0100 && words[1] === 0 && words[2] === 0 && words[3] === 0) return true;
    // Documentation 2001:db8::/32
    if (words[0] === 0x2001 && words[1] === 0x0db8) return true;
    // Benchmarking 2001:2::/48
    if (words[0] === 0x2001 && words[1] === 0x0002 && words[2] === 0) return true;
    // Orchidv2 2001:20::/28
    if (words[0] === 0x2001 && (words[1] & 0xfff0) === 0x0020) return true;

    return false;
  }

  // 3. Alternative IPv4 representations (octal, hex, 1-to-3 parts, 32-bit raw integers)
  const altOctets = parseIPv4Alternative(ip);
  if (altOctets) {
    return isPrivateIPv4Octets(altOctets[0], altOctets[1], altOctets[2], altOctets[3]);
  }

  return false;
}

/**
 * Validates whether a hostname string targets localhost, internal networks, or cloud metadata.
 */
export function isRestrictedHost(rawHost: string): boolean {
  if (!rawHost) return true;
  let host = rawHost.trim().toLowerCase();

  // If a full URL was passed, extract hostname
  if (/^https?:\/\//i.test(host)) {
    try {
      host = new URL(host).hostname;
    } catch {
      host = host.replace(/^https?:\/\//i, '').split('/')[0];
    }
  }

  // Strip port if present (avoid stripping IPv6 colons)
  if (host.includes(':') && !host.startsWith('[') && !host.includes('::')) {
    host = host.split(':')[0];
  }

  host = host.replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!host) return true;

  // Localhost checks
  if (host === 'localhost' || host.endsWith('.localhost')) return true;

  // Local / internal network suffixes
  if (
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.lan') ||
    host.endsWith('.corp') ||
    host.endsWith('.home') ||
    host.endsWith('.test') ||
    host.endsWith('.example') ||
    host.endsWith('.invalid')
  ) {
    return true;
  }

  // Cloud metadata hosts (AWS, GCP, Azure, Oracle, Alibaba)
  if (
    host === 'metadata.google.internal' ||
    host === 'metadata.goog' ||
    host === 'metadata' ||
    host === 'instance-data'
  ) {
    return true;
  }

  // If host is an IP representation, check against private IP list
  if (isPrivateIp(host)) return true;

  return false;
}

/**
 * Resolves a hostname and checks if any resolved IP is internal (anti-SSRF).
 * Returns the resolved address list if safe.
 */
export async function verifyHostSafe(hostname: string): Promise<string> {
  const cleanHost = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');

  if (isRestrictedHost(cleanHost)) {
    throw new Error(`Access to private, loopback, or internal host "${cleanHost}" is strictly prohibited (SSRF defense).`);
  }

  // If cleanHost is a direct IP literal, it already passed isRestrictedHost & isPrivateIp
  if (net.isIP(cleanHost) !== 0) {
    return cleanHost;
  }

  // DNS Resolution check
  try {
    const lookup = await dns.lookup(cleanHost, { all: true });
    if (!lookup || lookup.length === 0) {
      throw new Error(`Unable to resolve destination domain "${cleanHost}". The domain may be non-existent or inactive.`);
    }

    for (const entry of lookup) {
      if (isPrivateIp(entry.address)) {
        throw new Error(`Hostname ${cleanHost} resolves to private IP (${entry.address}), which is blocked.`);
      }
    }
    return lookup[0]?.address || cleanHost;
  } catch (err: unknown) {
    if (err instanceof Error && err.message.includes('blocked')) {
      throw err;
    }
    throw new Error(`Unable to resolve destination domain "${cleanHost}". The domain may be non-existent or inactive.`);
  }
}

/**
 * Validates a URL before outbound network requests.
 * Enforces supported HTTP/HTTPS schemes, non-empty hostnames, and standard web ports.
 */
export function validateUrlForScanning(rawInput: string): URL {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    throw new Error('Please enter a valid website URL to scan.');
  }

  // Reject control characters / non-printable bytes
  if (/[\x00-\x1F\x7F]/.test(trimmed)) {
    throw new Error('Malformed URL: Input contains invalid control characters or non-printable bytes.');
  }

  if (trimmed.length > 4096) {
    throw new Error('URL input is excessively long (exceeds 4096 characters). Please verify the link.');
  }

  // Reject unsupported schemes explicitly
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  let normalized = trimmed;

  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      throw new Error(
        `Unsupported URL scheme "${scheme}:". ScamLens only scans HTTP and HTTPS websites. Schemes like ${scheme}:, javascript:, file:, and data: are prohibited.`
      );
    }
  } else {
    normalized = 'https://' + trimmed;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error(`Malformed URL structure: "${trimmed}". Please provide a valid web domain or URL.`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.`);
  }

  // Reject embedded credentials (userinfo) in live scanning
  if (parsed.username || parsed.password || trimmed.includes('@')) {
    throw new Error('URLs containing embedded credentials or userinfo ("@" character) are prohibited from live sandbox scanning.');
  }

  const hostname = parsed.hostname;
  if (!hostname || hostname.length === 0) {
    throw new Error('Malformed URL: Destination hostname is missing.');
  }

  if (!isValidHostname(hostname)) {
    throw new Error(`Malformed URL: Destination hostname "${hostname}" is invalid or contains prohibited characters.`);
  }

  // Port restriction: only standard web ports allowed
  const port = parsed.port ? Number.parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
  const ALLOWED_PORTS = [80, 443, 8080, 8443];
  if (!ALLOWED_PORTS.includes(port)) {
    throw new Error(`Scanning non-standard port :${port} is prohibited. ScamLens only scans standard web ports (80, 443, 8080, 8443).`);
  }

  return parsed;
}

/**
 * Sanitizes system errors so internal file paths, stack traces, and environment details
 * are never leaked to external users.
 */
export function sanitizeErrorMessage(rawMessage: string): string {
  if (!rawMessage || typeof rawMessage !== 'string') {
    return 'An error occurred during sandbox scanning.';
  }

  // Preserve safe user-facing validation and security errors
  if (
    rawMessage.includes('SSRF defense') ||
    rawMessage.includes('strictly prohibited') ||
    rawMessage.includes('blocked') ||
    rawMessage.includes('Unsupported URL scheme') ||
    rawMessage.includes('Malformed URL') ||
    rawMessage.includes('non-standard port') ||
    rawMessage.includes('timed out') ||
    rawMessage.includes('Unable to resolve') ||
    rawMessage.includes('Excessive redirect loop') ||
    rawMessage.includes('Please enter a valid website URL') ||
    rawMessage.includes('embedded credentials') ||
    rawMessage.includes('control characters') ||
    rawMessage.includes('excessively long') ||
    rawMessage.includes('prohibited characters')
  ) {
    return rawMessage.replace(/\/[a-zA-Z0-9_\-./]+\.[a-zA-Z0-9]+/g, '').trim();
  }

  if (rawMessage.toLowerCase().includes('abort') || rawMessage.toLowerCase().includes('timeout')) {
    return 'Connection timed out. The target server did not respond within the time limit.';
  }

  if (rawMessage.toLowerCase().includes('econnrefused')) {
    return 'Failed to connect: Target server actively refused the connection.';
  }

  if (rawMessage.toLowerCase().includes('cert') || rawMessage.toLowerCase().includes('ssl') || rawMessage.toLowerCase().includes('tls')) {
    return 'Failed to establish a secure TLS/SSL connection with the target server.';
  }

  return 'Failed to connect to target site. The server may be unreachable, offline, or blocking scanner requests.';
}

/**
 * Custom Undici Dispatcher that verifies destination IPs at the socket level.
 * Defense-in-depth against DNS rebinding (TOCTOU) and direct socket SSRF.
 */
const rawUndiciConnector = buildConnector({
  lookup: (hostname, opts, cb) => {
    dnsCallback.lookup(hostname, { all: true }, (err, addresses) => {
      if (err) return (cb as any)(err, null, null);
      for (const entry of addresses) {
        if (isPrivateIp(entry.address)) {
          return (cb as any)(
            new Error(`SSRF Block: Host "${hostname}" resolves to restricted address (${entry.address}).`),
            null,
            null
          );
        }
      }
      if (opts.all) {
        (cb as any)(null, addresses);
      } else {
        (cb as any)(null, (addresses[0] as any).address, (addresses[0] as any).family);
      }
    });
  },
});

const safeUndiciConnector = (opts: any, cb: any) => {
  const rawHostname = opts.hostname || opts.host || '';
  const cleanHost = String(rawHostname).trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');

  if (isRestrictedHost(cleanHost)) {
    return cb(
      new Error(`SSRF Block: Direct connection to restricted destination "${cleanHost}" is prohibited.`)
    );
  }

  const port = Number(opts.port);
  const ALLOWED_PORTS = [80, 443, 8080, 8443];
  if (port && !ALLOWED_PORTS.includes(port)) {
    return cb(
      new Error(`Port :${port} is prohibited. ScamLens only connects to standard web ports (80, 443, 8080, 8443).`)
    );
  }

  rawUndiciConnector(opts, cb);
};

export const safeScanDispatcher = new Agent({
  connect: safeUndiciConnector,
  connectTimeout: 5000,
  headersTimeout: 6000,
  bodyTimeout: 6000,
});

/**
 * Sandboxed Live Website Scanner.
 */
export async function scanWebsiteInSandbox(rawUrl: string): Promise<SandboxScanResult> {
  const startTime = Date.now();
  const maxScanDurationMs = 15000; // Overall scan timeout 15 seconds

  // Pre-validate initial URL syntax, scheme, and port
  const initialParsed = validateUrlForScanning(rawUrl);
  let currentUrl = initialParsed.href;

  const redirectHops: Array<{ from: string; to: string; status: number }> = [];
  const maxRedirects = 5;
  let finalResponse: Response | null = null;
  let finalUrl = currentUrl;

  // Follow redirects safely with SSRF validation at every step
  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (Date.now() - startTime > maxScanDurationMs) {
      throw new Error('Sandbox scan timed out: Exceeded overall scan time limit of 15 seconds.');
    }

    const parsedUrl = validateUrlForScanning(currentUrl);

    // SSRF Pre-flight Host and DNS Check
    await verifyHostSafe(parsedUrl.hostname);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000); // 6s hop timeout

    let res: Response;
    try {
      res = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        dispatcher: safeScanDispatcher,
        signal: controller.signal,
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 ScamLens-Security-Sandbox/1.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Cache-Control': 'no-cache',
        },
      } as any);
    } catch (err: unknown) {
      clearTimeout(timeout);
      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error('Connection timed out after 6 seconds. The target server did not respond.');
      }
      const rawMsg = err instanceof Error ? (err as any).cause?.message || err.message : 'Connection failed';
      throw new Error(`Failed to connect to target site: ${rawMsg}`);
    } finally {
      clearTimeout(timeout);
    }

    // Handle redirects
    if (res.status >= 300 && res.status < 400 && res.headers.has('location')) {
      const location = res.headers.get('location')!;
      let resolvedNext: string;
      try {
        resolvedNext = new URL(location, currentUrl).href;
      } catch {
        throw new Error(`Malformed redirect target encountered: "${location}".`);
      }

      // Immediately validate redirect target scheme and port
      validateUrlForScanning(resolvedNext);

      redirectHops.push({
        from: currentUrl,
        to: resolvedNext,
        status: res.status,
      });

      if (hop === maxRedirects) {
        throw new Error('Excessive redirect loop detected (exceeded 5 redirects).');
      }

      currentUrl = resolvedNext;
      continue;
    }

    finalResponse = res;
    finalUrl = currentUrl;
    break;
  }

  if (!finalResponse) {
    throw new Error('Failed to obtain a valid HTTP response from target server.');
  }

  const responseTimeMs = Date.now() - startTime;
  const statusCode = finalResponse.status;
  const statusText = finalResponse.statusText;

  // Security Headers Inspection
  const hsts = finalResponse.headers.has('strict-transport-security');
  const contentSecurityPolicy = finalResponse.headers.has('content-security-policy');
  const xFrameOptions = finalResponse.headers.get('x-frame-options');
  const server = finalResponse.headers.get('server');

  // Read response body safely with strict size capping (max 2.5MB)
  const contentType = (finalResponse.headers.get('content-type') || '').toLowerCase();
  const isBinaryResource =
    contentType.startsWith('video/') ||
    contentType.startsWith('audio/') ||
    contentType.startsWith('image/') ||
    contentType.includes('application/octet-stream') ||
    contentType.includes('application/zip') ||
    contentType.includes('application/pdf') ||
    contentType.includes('application/x-tar') ||
    contentType.includes('application/gzip');

  let html = '';
  if (!isBinaryResource) {
    try {
      const reader = finalResponse.body?.getReader();
      if (reader) {
        const chunks: Uint8Array[] = [];
        let bytesRead = 0;
        const maxBytes = 2.5 * 1024 * 1024; // 2.5MB

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            bytesRead += value.length;
            chunks.push(value);
            if (bytesRead >= maxBytes) {
              await reader.cancel();
              break;
            }
          }
        }
        const totalBuffer = new Uint8Array(Math.min(bytesRead, maxBytes));
        let offset = 0;
        for (const c of chunks) {
          const toCopy = Math.min(c.length, totalBuffer.length - offset);
          totalBuffer.set(c.slice(0, toCopy), offset);
          offset += toCopy;
          if (offset >= totalBuffer.length) break;
        }
        html = new TextDecoder('utf-8', { fatal: false }).decode(totalBuffer);
      } else {
        const buffer = await finalResponse.arrayBuffer();
        const maxBytes = 2.5 * 1024 * 1024;
        const sliced = buffer.slice(0, maxBytes);
        html = new TextDecoder('utf-8', { fatal: false }).decode(sliced);
      }
    } catch {
      html = '';
    }
  }

  // Parse DOM with Cheerio
  const $ = cheerio.load(html);

  // Extract Metadata
  const pageTitle = $('title').first().text().trim() || 'No Title Found';
  const metaDescription =
    $('meta[name="description"]').attr('content')?.trim() ||
    $('meta[property="og:description"]').attr('content')?.trim() ||
    '';

  // 1. Form & Credential Theft Analysis
  const forms = $('form');
  const totalForms = forms.length;
  let hasPasswordInput = false;
  let hasOtpInput = false;
  let hasCreditCardInput = false;
  let hasExternalFormAction = false;
  const externalActionUrls: string[] = [];
  let insecureHttpForms = false;

  const finalParsed = new URL(finalUrl);
  const targetHost = finalParsed.hostname.toLowerCase();
  const { rootDomain: targetRootDomain } = parseDomainStructure(targetHost);

  $('input').each((_i, el) => {
    const type = $(el).attr('type')?.toLowerCase() || 'text';
    const name = $(el).attr('name')?.toLowerCase() || '';
    const id = $(el).attr('id')?.toLowerCase() || '';
    const placeholder = $(el).attr('placeholder')?.toLowerCase() || '';
    const combinedAttr = `${name} ${id} ${placeholder}`;

    if (type === 'password') {
      hasPasswordInput = true;
    }

    if (/(?:otp|one[-_]?time|mpin|verification[-_]?code)/i.test(combinedAttr)) {
      hasOtpInput = true;
    }

    if (/(?:card[-_]?num|credit[-_]?card|debit[-_]?card|cvv|cvc|card[-_]?exp)/i.test(combinedAttr)) {
      hasCreditCardInput = true;
    }
  });

  forms.each((_i, form) => {
    const action = $(form).attr('action')?.trim();
    if (action && action !== '#' && !action.startsWith('javascript:')) {
      try {
        const resolvedAction = new URL(action, finalUrl);
        if (resolvedAction.protocol === 'http:') {
          insecureHttpForms = true;
        }
        const actionHost = resolvedAction.hostname.toLowerCase();
        const { rootDomain: actionRootDomain } = parseDomainStructure(actionHost);

        if (actionRootDomain && actionRootDomain !== targetRootDomain) {
          hasExternalFormAction = true;
          if (!externalActionUrls.includes(resolvedAction.href)) {
            externalActionUrls.push(resolvedAction.href);
          }
        }
      } catch {
        // Ignore malformed actions
      }
    }
  });

  // 2. Script & Iframe Analysis
  let externalScriptCount = 0;
  $('script[src]').each((_i, el) => {
    const src = $(el).attr('src')?.trim();
    if (src) {
      try {
        const scriptUrl = new URL(src, finalUrl);
        const { rootDomain: scriptRoot } = parseDomainStructure(scriptUrl.hostname);
        if (scriptRoot !== targetRootDomain) {
          externalScriptCount++;
        }
      } catch {
        // Ignore
      }
    }
  });

  const iframeSources: string[] = [];
  $('iframe').each((_i, el) => {
    const src = $(el).attr('src')?.trim();
    if (src && !iframeSources.includes(src)) {
      iframeSources.push(src);
    }
  });

  // 3. Page Content Scam Analysis (Feeding live body text into ScamLens Message Analyzer)
  $('script, style, noscript, svg, head').remove();
  const visibleText = $('body').text().replace(/\s+/g, ' ').trim().slice(0, 8000);
  const contentAnalysis = visibleText.length > 20 ? analyzeMessage(visibleText) : null;

  // 4. Sandbox Flags & Scoring
  const sandboxFlags: UrlFlag[] = [];
  let sandboxScore = 0;

  // Critical Form Flags
  if (hasPasswordInput && hasExternalFormAction) {
    sandboxScore += 45;
    sandboxFlags.push({
      id: 'sb_flag_cross_domain_credential_theft',
      name: 'Cross-Domain Credential Harvesting Form',
      severity: 'critical',
      description: 'The page presents a password field that submits credentials to an entirely different foreign domain.',
      detail: `The login form on ${targetHost} sends submitted authentication data to "${externalActionUrls[0] || 'external server'}". This is an acute hallmark of phishing credential harvesters.`,
    });
  } else if (hasPasswordInput && !finalUrl.startsWith('https://')) {
    sandboxScore += 40;
    sandboxFlags.push({
      id: 'sb_flag_unencrypted_password_form',
      name: 'Insecure Unencrypted Password Submission',
      severity: 'critical',
      description: 'Page requests passwords over unencrypted HTTP.',
      detail: 'Entering credentials on an HTTP form exposes student passwords in cleartext across the local network.',
    });
  } else if (hasPasswordInput) {
    sandboxScore += 15;
    sandboxFlags.push({
      id: 'sb_flag_login_form_detected',
      name: 'Authentication Form Detected',
      severity: 'warning',
      description: 'Page contains a user credential login/password form.',
      detail: 'Ensure this is the genuine official institution domain before submitting any authentication details.',
    });
  }

  if (hasOtpInput || hasCreditCardInput) {
    sandboxScore += 30;
    sandboxFlags.push({
      id: 'sb_flag_financial_otp_fields',
      name: 'Sensitive OTP or Financial Card Fields',
      severity: 'critical',
      description: 'Page requests confidential OTP verification codes, MPINs, or card details.',
      detail: 'Legitimate portals rarely request OTPs or CVVs directly on unsolicited web links.',
    });
  }

  if (insecureHttpForms) {
    sandboxScore += 25;
    sandboxFlags.push({
      id: 'sb_flag_insecure_form_action',
      name: 'Insecure HTTP Form Action',
      severity: 'high',
      description: 'Form submission directs over plain unencrypted HTTP.',
      detail: 'Form submissions must be secured with TLS (HTTPS) to prevent interception.',
    });
  }

  // Redirect Cloaking
  if (redirectHops.length >= 2) {
    sandboxScore += 25;
    sandboxFlags.push({
      id: 'sb_flag_redirect_chain',
      name: `Multi-Hop Redirect Chain (${redirectHops.length} hops)`,
      severity: 'high',
      description: `The URL passed through ${redirectHops.length} intermediate redirects before landing on final destination.`,
      detail: `Scammers use multi-hop redirect chains to conceal the destination from automated scanners. Landed on: ${finalUrl}`,
    });
  }

  // Missing Modern Security Headers
  if (!hsts && finalUrl.startsWith('https://')) {
    sandboxFlags.push({
      id: 'sb_flag_missing_hsts',
      name: 'Missing HTTP Strict Transport Security (HSTS)',
      severity: 'warning',
      description: 'The server does not enforce HSTS protection.',
      detail: 'HSTS guarantees that web browsers only communicate over HTTPS, preventing SSL stripping downgrades.',
    });
    sandboxScore += 10;
  }

  if (!contentSecurityPolicy) {
    sandboxFlags.push({
      id: 'sb_flag_missing_csp',
      name: 'Missing Content Security Policy (CSP)',
      severity: 'warning',
      description: 'The server does not publish a Content Security Policy.',
      detail: 'Absence of CSP increases vulnerability to malicious cross-site scripting (XSS) and credential injection.',
    });
  }

  // Content Scam Triggers from Message Analyzer
  let detectedContentScore = 0;
  const contentWarnings: Array<{ id: string; title: string; category: string; severity: string; explanation: string }> = [];
  const contentSnippets: string[] = [];

  if (contentAnalysis && contentAnalysis.score >= 25) {
    detectedContentScore = contentAnalysis.score;
    sandboxScore += Math.min(35, Math.round(contentAnalysis.score * 0.4));

    for (const w of contentAnalysis.warningSigns) {
      contentWarnings.push({
        id: w.id,
        title: w.title,
        category: w.category,
        severity: w.severity,
        explanation: w.explanation,
      });
      contentSnippets.push(...w.matchedSnippets);
    }

    sandboxFlags.push({
      id: 'sb_flag_scam_content_detected',
      name: `On-Page Social Engineering Signals Detected (Score: ${contentAnalysis.score})`,
      severity: contentAnalysis.verdict === 'SCAM' ? 'critical' : 'high',
      description: `The live text content on this page contains patterns matching "${contentAnalysis.warningSigns.map((w) => w.title).slice(0, 2).join('", "')}".`,
      detail: 'The sandboxed content scanner found deceptive phrasing inside the page body itself.',
    });
  }

  // Combined score capping
  const combinedScore = Math.min(100, Math.max(0, sandboxScore));
  let combinedVerdict: UrlRiskLevel = 'SAFE';
  if (combinedScore >= 60) {
    combinedVerdict = 'SUSPICIOUS';
  } else if (combinedScore >= 25) {
    combinedVerdict = 'RISKY';
  } else {
    combinedVerdict = 'SAFE';
  }

  // Summary
  let summary = '';
  if (combinedVerdict === 'SUSPICIOUS') {
    summary = `Live sandbox scan found critical high-risk indicators (${sandboxFlags.filter((f) => f.severity === 'critical').length} critical flags). Extreme caution advised.`;
  } else if (combinedVerdict === 'RISKY') {
    summary = `Live sandbox scan detected suspicious warning signs (${sandboxFlags.length} flags). Verify before entering credentials.`;
  } else {
    summary = `Live sandbox scan completed. Target server responded (${statusCode} ${statusText}) with standard page structure.`;
  }

  // Recommendations
  const recommendations: string[] = [];
  if (hasPasswordInput && hasExternalFormAction) {
    recommendations.push('DO NOT enter any passwords on this site. Form submissions are routed to an external third-party domain.');
  }
  if (hasOtpInput || hasCreditCardInput) {
    recommendations.push('Never reveal OTPs, banking PINs, or card CVVs on unsolicited websites.');
  }
  if (redirectHops.length >= 2) {
    recommendations.push('Inspect the final landing domain carefully; multi-hop redirects are often used to evade security scanners.');
  }
  if (combinedScore < 25) {
    recommendations.push('Page structure appears standard, but always verify domain identity before entering confidential information.');
  }

  return {
    targetUrl: rawUrl,
    finalUrl,
    statusCode,
    statusText,
    responseTimeMs,
    redirectHops,
    pageTitle,
    metaDescription,
    isLive: true,
    securityHeaders: {
      hsts,
      contentSecurityPolicy,
      xFrameOptions,
      server,
    },
    formAnalysis: {
      totalForms,
      hasPasswordInput,
      hasOtpInput,
      hasCreditCardInput,
      hasExternalFormAction,
      externalActionUrls,
      insecureHttpForms,
    },
    scriptAnalysis: {
      externalScriptCount,
      iframeCount: iframeSources.length,
      iframeSources,
    },
    contentScamSignals: {
      detectedScore: detectedContentScore,
      warningSigns: contentWarnings,
      matchedSnippets: contentSnippets.slice(0, 5),
    },
    sandboxFlags,
    sandboxScore,
    combinedScore,
    combinedVerdict,
    summary,
    recommendations,
    timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
  };
}
