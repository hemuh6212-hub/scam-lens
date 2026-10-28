/**
 * ScamLens Clipboard & Summary Export Utility
 * Provides safe URL defanging, standardized plain-text security report generators,
 * and robust clipboard copy with fallback and guaranteed failure reporting.
 */

import { MessageAnalysisResult, UrlAnalysisResult, SandboxScanResult } from '../types/analyzer';

/**
 * Defang a URL or domain so it cannot be accidentally clicked or unfurled when copied
 * into chats, tickets, or emails.
 * e.g., "https://evil.bank-login.xyz/otp" -> "hxxps://evil[.]bank-login[.]xyz/otp"
 */
export function defangUrl(rawUrl: string): string {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  return rawUrl
    .trim()
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/\./g, '[.]');
}

/**
 * Defang a hostname or domain name
 * e.g., "login.hdfcbank-verify.xyz" -> "login[.]hdfcbank-verify[.]xyz"
 */
export function defangHost(host: string): string {
  if (!host || typeof host !== 'string') return '';
  return host.trim().replace(/\./g, '[.]');
}

/**
 * Robust clipboard copy function supporting modern navigator.clipboard
 * with fallback to document.execCommand('copy').
 *
 * CRITICAL RULE: Never returns success: true unless the clipboard write
 * was actually verified to succeed.
 */
export async function copyTextToClipboard(text: string): Promise<{ success: boolean; error?: string }> {
  if (!text) {
    return { success: false, error: 'No content available to copy.' };
  }

  // 1. Try modern navigator.clipboard.writeText if available and in secure context
  if (
    typeof navigator !== 'undefined' &&
    navigator.clipboard &&
    typeof navigator.clipboard.writeText === 'function'
  ) {
    try {
      await navigator.clipboard.writeText(text);
      return { success: true };
    } catch {
      // Permission denied, focus lost, or blocked in iframe — proceed to fallback
    }
  }

  // 2. Fallback using temporary textarea and document.execCommand('copy')
  if (typeof document !== 'undefined' && typeof document.createElement === 'function') {
    try {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      // Position offscreen to avoid visual jump or page scrolling
      textarea.style.position = 'fixed';
      textarea.style.top = '0';
      textarea.style.left = '-9999px';
      textarea.style.opacity = '0';
      textarea.setAttribute('readonly', '');
      document.body.appendChild(textarea);
      textarea.select();
      textarea.setSelectionRange(0, textarea.value.length);

      const successful = document.execCommand('copy');
      document.body.removeChild(textarea);

      if (successful) {
        return { success: true };
      }
      return {
        success: false,
        error: 'Browser blocked clipboard access. Please check permissions or copy manually.',
      };
    } catch (err: unknown) {
      return {
        success: false,
        error: err instanceof Error ? err.message : 'Clipboard operation failed.',
      };
    }
  }

  return {
    success: false,
    error: 'Clipboard API is not supported in this browser environment.',
  };
}

/**
 * Generates plain-text analysis summary for Message Scam Analyzer.
 * Contains:
 * - Verdict and risk score
 * - Actual detected warning categories
 * - Matching evidence phrases where available
 * - Plain-English explanations
 * - Relevant safety recommendations
 * - Clear statement that heuristic results cannot guarantee authenticity
 */
export function generateMessageAnalysisReport(result: MessageAnalysisResult): string {
  if (!result) return '';

  const warningList =
    result.warningSigns && result.warningSigns.length > 0
      ? result.warningSigns
          .map((w, idx) => {
            const evidence =
              w.matchedSnippets && w.matchedSnippets.length > 0
                ? w.matchedSnippets.map((s) => `"${s}"`).join(', ')
                : 'Pattern context match';
            return [
              `${idx + 1}. ${w.title} [${w.severity.toUpperCase()}] (+${w.points} pts)`,
              `   Category: ${w.category}`,
              `   Matched Evidence: ${evidence}`,
              `   Explanation: ${w.explanation}`,
              `   Guidance: ${w.recommendation}`,
            ].join('\n');
          })
          .join('\n\n')
      : 'No warning indicators detected by current heuristic rules.';

  const linksList =
    result.extractedUrls && result.extractedUrls.length > 0
      ? result.extractedUrls.map((u) => ` - ${defangUrl(u)}`).join('\n')
      : 'None detected.';

  const recList =
    result.recommendations && result.recommendations.length > 0
      ? result.recommendations.map((r) => ` - ${r}`).join('\n')
      : ' - Exercise general caution when receiving unsolicited messages.';

  return [
    '=========================================',
    'SCAMLENS MESSAGE EVALUATION REPORT',
    '=========================================',
    `Verdict: ${result.verdict}`,
    `Heuristic Risk Score: ${result.score} / 100`,
    `Analysis Timestamp: ${result.analysisTimestamp}`,
    `Words Analyzed: ${result.totalAnalyzedWords}`,
    '',
    'VERDICT SUMMARY:',
    result.verdictSummary,
    '',
    `WHY THIS MESSAGE WAS FLAGGED (${result.warningSigns?.length || 0} Indicators Detected):`,
    warningList,
    '',
    `EXTRACTED WEB LINKS (Sanitized) (${result.extractedUrls?.length || 0}):`,
    linksList,
    '',
    'RECOMMENDED SAFETY ACTIONS:',
    recList,
    '',
    'HEURISTIC NOTICE & LIMITATIONS:',
    'Heuristic analysis results cannot guarantee message authenticity or safety. Legitimate-looking messages can still be fraudulent, and authentic campus notices may occasionally mention flagged keywords. Always independently verify unexpected or high-stakes requests via official university or bank contact numbers.',
    '=========================================',
  ].join('\n');
}

/**
 * Generates plain-text analysis summary for URL Structural Inspector.
 * Contains:
 * - Appropriately sanitized URL and hostname
 * - Verdict and risk score
 * - Actual detected indicators (warnings and informational)
 * - Relevant explanations and safety recommendations
 * - Clear limitations notice to avoid overstating results
 */
export function generateUrlStructuralReport(result: UrlAnalysisResult): string {
  if (!result) return '';

  const warningFlags = (result.flags || []).filter((f) => f.severity !== 'info');
  const infoFlags = (result.flags || []).filter((f) => f.severity === 'info');

  const warningText =
    warningFlags.length > 0
      ? warningFlags
          .map(
            (f, idx) =>
              `${idx + 1}. ${f.name} [${f.severity.toUpperCase()}]\n   - Explanation: ${f.description}\n   - Technical Detail: ${f.detail}`
          )
          .join('\n\n')
      : 'No structural warning signs detected.';

  const infoText =
    infoFlags.length > 0
      ? infoFlags
          .map(
            (f, idx) =>
              `${idx + 1}. ${f.name}\n   - Explanation: ${f.description}\n   - Technical Detail: ${f.detail}`
          )
          .join('\n\n')
      : 'None.';

  const recList =
    result.recommendations && result.recommendations.length > 0
      ? result.recommendations.map((r) => ` - ${r}`).join('\n')
      : ' - Always verify authentic destination domains independently.';

  return [
    '=========================================',
    'SCAMLENS URL STRUCTURAL INSPECTION REPORT',
    '=========================================',
    `Target URL (Sanitized): ${defangUrl(result.inputUrl)}`,
    `Normalized URL (Sanitized): ${defangUrl(result.normalizedUrl)}`,
    `Target Hostname: ${result.hostname}`,
    `Root Registered Domain: ${result.rootDomain}`,
    `Effective Suffix (TLD): .${result.effectiveTld || 'none'}`,
    `Host Architecture: ${result.isIpAddress ? 'Direct Numeric IP Address' : 'Named Domain'}`,
    `Path: ${result.pathname || '/'}`,
    `Query Parameters: ${result.searchParams || 'none'}`,
    '',
    `Verdict: ${result.verdict}`,
    `Structural Risk Score: ${result.riskScore} / 100`,
    `Warning Indicators Count: ${result.warningCount}`,
    `Analysis Timestamp: ${result.analysisTimestamp}`,
    `Summary: ${result.summary}`,
    '',
    `STRUCTURAL WARNING INDICATORS (${warningFlags.length}):`,
    warningText,
    '',
    `INSTITUTIONAL & TRUST VERIFICATION SIGNALS (${infoFlags.length}):`,
    infoText,
    '',
    'RECOMMENDED SAFETY ACTIONS:',
    recList,
    '',
    'EVALUATION SCOPE & LIMITATIONS:',
    'This structural inspection is performed locally in browser memory based on URL syntax and domain composition. It does not query external threat blacklists or download destination server files. A low score or SAFE verdict cannot guarantee that a destination website is benign or uncompromised. Always exercise caution before disclosing passwords or personal data.',
    '=========================================',
  ].join('\n');
}

/**
 * Generates plain-text analysis summary for Live Sandbox Scan.
 * Contains:
 * - Appropriately sanitized target and landing URLs
 * - Combined verdict and risk scores
 * - Actual detected indicators (HTTP status, redirect hops, forms, on-page signals, headers)
 * - Relevant explanations and safety recommendations
 * - Clear limitations notice
 */
export function generateSandboxScanReport(s: SandboxScanResult): string {
  if (!s) return '';

  const recList =
    s.recommendations && s.recommendations.length > 0
      ? s.recommendations.map((r) => ` - ${r}`).join('\n')
      : ' - Exercise caution before interacting with this site.';

  const onPageSignals =
    s.contentScamSignals?.warningSigns && s.contentScamSignals.warningSigns.length > 0
      ? s.contentScamSignals.warningSigns
          .map((w) => ` - [${w.severity.toUpperCase()}] ${w.title}: ${w.explanation}`)
          .join('\n')
      : ' - None detected in visible page text.';

  return [
    '=========================================',
    'SCAMLENS LIVE WEBSITE SANDBOX SCAN REPORT',
    '=========================================',
    `Target URL (Sanitized): ${defangUrl(s.targetUrl)}`,
    `Final Landing URL (Sanitized): ${defangUrl(s.finalUrl)}`,
    `HTTP Status: ${s.statusCode} ${s.statusText}`,
    `Response Time: ${s.responseTimeMs} ms`,
    `Combined Verdict: ${s.combinedVerdict}`,
    `Combined Threat Score: ${s.combinedScore} / 100`,
    `Page Title: ${s.pageTitle || 'Untitled'}`,
    `Meta Description: ${s.metaDescription || 'None'}`,
    '',
    'REDIRECT CHAIN (Sanitized):',
    s.redirectHops && s.redirectHops.length > 0
      ? s.redirectHops.map((h, i) => `  ${i + 1}. [HTTP ${h.status}] ${defangUrl(h.from)} -> ${defangUrl(h.to)}`).join('\n')
      : '  Direct connection (0 redirects)',
    '',
    'FORM & CREDENTIAL AUDIT:',
    `- Total Forms: ${s.formAnalysis?.totalForms ?? 0}`,
    `- Password Input Present: ${s.formAnalysis?.hasPasswordInput ? 'YES (HIGH RISK)' : 'No'}`,
    `- OTP / Card Fields: ${s.formAnalysis?.hasOtpInput || s.formAnalysis?.hasCreditCardInput ? 'YES (CRITICAL)' : 'No'}`,
    `- External Form Action: ${s.formAnalysis?.hasExternalFormAction ? `YES -> ${s.formAnalysis.externalActionUrls.map(defangUrl).join(', ')}` : 'No'}`,
    `- Unencrypted HTTP Forms: ${s.formAnalysis?.insecureHttpForms ? 'YES (INSECURE)' : 'No'}`,
    '',
    'SECURITY HEADERS:',
    `- HSTS: ${s.securityHeaders?.hsts ? 'Enforced' : 'Missing'}`,
    `- CSP: ${s.securityHeaders?.contentSecurityPolicy ? 'Published' : 'Missing'}`,
    `- X-Frame-Options: ${s.securityHeaders?.xFrameOptions || 'Not set'}`,
    `- Server: ${s.securityHeaders?.server || 'Hidden'}`,
    '',
    'ON-PAGE SOCIAL ENGINEERING SIGNALS:',
    onPageSignals,
    '',
    'RECOMMENDED SAFETY ACTIONS:',
    recList,
    '',
    'EVALUATION SCOPE & LIMITATIONS:',
    'Live sandbox scanning inspects point-in-time responses, headers, and DOM elements captured through an isolated backend proxy. It cannot guarantee immunity from dynamic cloaking, geofenced threats, or server-side compromises. It does not constitute a real-time antivirus or anti-phishing warranty. Always independently verify domain ownership before submitting personal credentials.',
    '=========================================',
  ].join('\n');
}
