/**
 * Verification test suite for ScamLens Copy Analysis Summary functionality
 * Tests report generator contents, URL sanitization/defanging, indicator integrity,
 * limitations disclaimers, and clipboard error-handling contracts.
 */

import { analyzeMessage } from './src/utils/messageAnalyzer';
import { analyzeUrl } from './src/utils/urlAnalyzer';
import {
  defangUrl,
  defangHost,
  generateMessageAnalysisReport,
  generateUrlStructuralReport,
  generateSandboxScanReport,
  copyTextToClipboard,
} from './src/utils/clipboard';
import { SandboxScanResult } from './src/types/analyzer';

let passed = 0;
let failed = 0;

function assert(condition: boolean, desc: string) {
  if (condition) {
    passed++;
    console.log(`  [PASS] ${desc}`);
  } else {
    failed++;
    console.error(`  [FAIL] ${desc}`);
  }
}

async function runTests() {
  console.log('======================================================');
  console.log('SCAMLENS COPY FUNCTIONALITY & SUMMARY VERIFICATION');
  console.log('======================================================\n');

  // TEST SUITE 1: URL & Host Defanging / Sanitization
  console.log('--- TEST SUITE 1: URL & Hostname Sanitization ---');
  assert(
    defangUrl('http://phishing-site.xyz/login.php') === 'hxxp://phishing-site[.]xyz/login[.]php',
    'defangUrl replaces http:// with hxxp:// and dots with [.]'
  );
  assert(
    defangUrl('https://secure-hdfc.fake.com/verify?otp=123') === 'hxxps://secure-hdfc[.]fake[.]com/verify?otp=123',
    'defangUrl replaces https:// with hxxps:// and domain dots with [.]'
  );
  assert(
    defangHost('login.student-portal.xyz') === 'login[.]student-portal[.]xyz',
    'defangHost defangs domain dots'
  );
  assert(defangUrl('') === '', 'defangUrl handles empty inputs safely');

  // TEST SUITE 2: Message Analysis Report Content
  console.log('\n--- TEST SUITE 2: Message Analysis Summary Generation ---');
  const scamMsg = `Dear Customer, unusual activity has been detected on your bank account. To prevent account suspension, verify your identity immediately by submitting your banking credentials and OTP through our verification portal: http://sbi-verification.info. Failure to complete verification within 15 minutes may result in restricted access.`;
  const scamRes = analyzeMessage(scamMsg);
  const scamReport = generateMessageAnalysisReport(scamRes);

  assert(scamReport.includes('SCAMLENS MESSAGE EVALUATION REPORT'), 'Contains header');
  assert(scamReport.includes(`Verdict: ${scamRes.verdict}`), 'Contains correct verdict');
  assert(scamReport.includes(`Heuristic Risk Score: ${scamRes.score} / 100`), 'Contains risk score out of 100');
  assert(scamReport.includes(`Analysis Timestamp: ${scamRes.analysisTimestamp}`), 'Contains analysis timestamp');
  assert(scamReport.includes('VERDICT SUMMARY:'), 'Contains verdict summary section');
  assert(scamReport.includes('WHY THIS MESSAGE WAS FLAGGED'), 'Contains explainability breakdown');

  // Check actual warning categories & evidence
  for (const w of scamRes.warningSigns) {
    assert(scamReport.includes(`Category: ${w.category}`), `Contains category: ${w.category}`);
    assert(scamReport.includes(`Explanation: ${w.explanation}`), `Contains plain-English explanation for ${w.title}`);
    assert(scamReport.includes(`Guidance: ${w.recommendation}`), `Contains safety guidance for ${w.title}`);
  }
  assert(scamReport.includes('Matched Evidence:'), 'Contains matching evidence section');
  assert(scamReport.includes('RECOMMENDED SAFETY ACTIONS:'), 'Contains safety actions');
  assert(
    scamReport.includes('HEURISTIC NOTICE & LIMITATIONS:') &&
    scamReport.includes('cannot guarantee message authenticity or safety'),
    'Contains required authenticity & heuristic disclaimer'
  );
  assert(
    scamReport.includes('hxxp://sbi-verification[.]info'),
    'Extracted URLs are properly defanged/sanitized in the report'
  );

  // Test genuine campus message (SAFE) - no fabricated indicators
  const safeMsg = `All students are reminded that the library will remain open until 10:00 PM during exam week. Please return reserved books on time.`;
  const safeRes = analyzeMessage(safeMsg);
  const safeReport = generateMessageAnalysisReport(safeRes);

  assert(safeReport.includes('Verdict: SAFE'), 'Safe message has Verdict: SAFE');
  assert(safeReport.includes('No warning indicators detected by current heuristic rules.'), 'No fabricated warning signs for safe message');
  assert(safeReport.includes('HEURISTIC NOTICE & LIMITATIONS:'), 'Safe message report still includes disclaimer to avoid overstating');

  // TEST SUITE 3: URL Structural Inspection Report Content
  console.log('\n--- TEST SUITE 3: URL Structural Report Generation ---');
  const urlToCheck = 'http://192.168.1.1:8080/student-login.php?session=abc';
  const urlRes = analyzeUrl(urlToCheck);
  const urlReport = generateUrlStructuralReport(urlRes);

  assert(urlReport.includes('SCAMLENS URL STRUCTURAL INSPECTION REPORT'), 'Contains URL report header');
  assert(urlReport.includes('Target URL (Sanitized): hxxp://192[.]168[.]1[.]1:8080/student-login[.]php?session=abc'), 'Sanitizes target URL');
  assert(urlReport.includes(`Target Hostname: ${urlRes.hostname}`), 'Includes analyzed hostname');
  assert(urlReport.includes(`Verdict: ${urlRes.verdict}`), 'Includes structural verdict');
  assert(urlReport.includes(`Structural Risk Score: ${urlRes.riskScore} / 100`), 'Includes structural risk score');
  assert(urlReport.includes('STRUCTURAL WARNING INDICATORS'), 'Includes actual detected warning flags');
  assert(urlReport.includes('RECOMMENDED SAFETY ACTIONS:'), 'Includes safety recommendations');
  assert(
    urlReport.includes('EVALUATION SCOPE & LIMITATIONS:') &&
    urlReport.includes('does not query external threat blacklists') &&
    urlReport.includes('cannot guarantee that a destination website is benign'),
    'Includes necessary scope & limitations statement to avoid overstating'
  );

  // TEST SUITE 4: Sandbox Scan Report Content
  console.log('\n--- TEST SUITE 4: Live Sandbox Scan Report Generation ---');
  const mockSandbox: SandboxScanResult = {
    targetUrl: 'http://malicious-portal.xyz/verify',
    finalUrl: 'http://malicious-portal.xyz/fake-login',
    statusCode: 200,
    statusText: 'OK',
    responseTimeMs: 312,
    redirectHops: [{ from: 'http://malicious-portal.xyz/verify', to: 'http://malicious-portal.xyz/fake-login', status: 302 }],
    pageTitle: 'Official University Account Update',
    metaDescription: 'Please enter your student password and card info',
    isLive: true,
    securityHeaders: {
      hsts: false,
      contentSecurityPolicy: false,
      xFrameOptions: null,
      server: 'Apache',
    },
    formAnalysis: {
      totalForms: 1,
      hasPasswordInput: true,
      hasOtpInput: true,
      hasCreditCardInput: false,
      hasExternalFormAction: true,
      externalActionUrls: ['http://harvest.ru/steal'],
      insecureHttpForms: true,
    },
    scriptAnalysis: {
      externalScriptCount: 2,
      iframeCount: 0,
      iframeSources: [],
    },
    contentScamSignals: {
      detectedScore: 65,
      warningSigns: [
        { id: 'urgency', title: 'Artificial Urgency', category: 'Urgency', severity: 'high', explanation: 'Pressures user to act quickly' }
      ],
      matchedSnippets: ['immediate action required'],
    },
    sandboxFlags: [],
    sandboxScore: 70,
    combinedScore: 85,
    combinedVerdict: 'SUSPICIOUS',
    summary: 'Detected credential harvesting form and unencrypted HTTP communication.',
    recommendations: ['Do NOT enter credentials.', 'Report this site to IT security.'],
    timestamp: '12:00:00 PM',
  };

  const sandboxReport = generateSandboxScanReport(mockSandbox);
  assert(sandboxReport.includes('SCAMLENS LIVE WEBSITE SANDBOX SCAN REPORT'), 'Contains sandbox report header');
  assert(sandboxReport.includes('Target URL (Sanitized): hxxp://malicious-portal[.]xyz/verify'), 'Defangs target URL');
  assert(sandboxReport.includes('Final Landing URL (Sanitized): hxxp://malicious-portal[.]xyz/fake-login'), 'Defangs landing URL');
  assert(sandboxReport.includes('Combined Verdict: SUSPICIOUS'), 'Includes combined verdict');
  assert(sandboxReport.includes('Combined Threat Score: 85 / 100'), 'Includes combined threat score');
  assert(sandboxReport.includes('Password Input Present: YES (HIGH RISK)'), 'Includes form audit password detection');
  assert(sandboxReport.includes('OTP / Card Fields: YES (CRITICAL)'), 'Includes OTP detection');
  assert(sandboxReport.includes('hxxp://harvest[.]ru/steal'), 'Defangs external form action URLs');
  assert(
    sandboxReport.includes('EVALUATION SCOPE & LIMITATIONS:') &&
    sandboxReport.includes('cannot guarantee immunity from dynamic cloaking'),
    'Includes sandbox limitations statement'
  );

  // TEST SUITE 5: Clipboard Behavior & Error-Handling Guarantees
  console.log('\n--- TEST SUITE 5: Clipboard Error Handling & Verification ---');
  
  // 5a. Empty string test
  const emptyRes = await copyTextToClipboard('');
  assert(emptyRes.success === false && !!emptyRes.error, 'Empty string returns success: false with clear error');

  // 5b. Browser environment mocking: Modern navigator.clipboard success
  const originalNavigatorDesc = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const originalDocumentDesc = Object.getOwnPropertyDescriptor(globalThis, 'document');

  let writtenText = '';
  Object.defineProperty(globalThis, 'navigator', {
    value: {
      clipboard: {
        writeText: async (t: string) => {
          writtenText = t;
        },
      },
    },
    configurable: true,
    writable: true,
  });

  const modernRes = await copyTextToClipboard('Test summary payload');
  assert(modernRes.success === true && writtenText === 'Test summary payload', 'Modern navigator.clipboard.writeText succeeds and copies text');

  // 5c. Navigator writeText throws -> fall back to document.execCommand
  let execCommandCalled = false;
  let execCommandParam = '';
  let textareaAppended = false;
  let textareaRemoved = false;

  Object.defineProperty(globalThis, 'navigator', {
    value: {
      clipboard: {
        writeText: async () => {
          throw new Error('NotAllowedError: Document is not focused');
        },
      },
    },
    configurable: true,
    writable: true,
  });

  const mockDoc = {
    createElement: (_tag: string) => {
      const el: any = {
        style: {},
        value: '',
        select: () => {},
        setSelectionRange: () => {},
        setAttribute: () => {},
      };
      return el;
    },
    body: {
      appendChild: () => { textareaAppended = true; },
      removeChild: () => { textareaRemoved = true; },
    },
    execCommand: (cmd: string) => {
      execCommandCalled = true;
      execCommandParam = cmd;
      return true; // fallback success
    },
  };

  Object.defineProperty(globalThis, 'document', {
    value: mockDoc,
    configurable: true,
    writable: true,
  });

  const fallbackRes = await copyTextToClipboard('Fallback test payload');
  assert(
    fallbackRes.success === true &&
    execCommandCalled &&
    execCommandParam === 'copy' &&
    textareaAppended &&
    textareaRemoved,
    'Falls back cleanly to document.execCommand when navigator.clipboard rejects'
  );

  // 5d. Both navigator.clipboard AND document.execCommand fail (returns false)
  // CRITICAL REQUIREMENT: NEVER falsely show success/copied!
  mockDoc.execCommand = () => false;

  const failureRes = await copyTextToClipboard('Failure payload');
  assert(
    failureRes.success === false &&
    typeof failureRes.error === 'string' &&
    failureRes.error.length > 0,
    'Returns success: false with informative error when execCommand returns false (NEVER falsely reports success)'
  );

  // 5e. document.execCommand throws an exception
  mockDoc.execCommand = () => {
    throw new Error('SecurityError: Permission denied');
  };

  const thrownRes = await copyTextToClipboard('Thrown error payload');
  assert(
    thrownRes.success === false &&
    thrownRes.error === 'SecurityError: Permission denied',
    'Catches exceptions cleanly and returns success: false with thrown message'
  );

  // Restore globals
  if (originalNavigatorDesc) {
    Object.defineProperty(globalThis, 'navigator', originalNavigatorDesc);
  } else {
    // @ts-expect-error cleanup
    delete globalThis.navigator;
  }
  if (originalDocumentDesc) {
    Object.defineProperty(globalThis, 'document', originalDocumentDesc);
  } else {
    // @ts-expect-error cleanup
    delete globalThis.document;
  }

  console.log('\n======================================================');
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('======================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
