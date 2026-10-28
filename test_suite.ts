/**
 * ScamLens Repeatable Automated Test Suite
 * Comprehensive verification of all 16 Message Test Categories and 20 URL Test Categories
 * as specified in Section 7 of the engineering audit specification.
 */

import { analyzeUrl } from './src/utils/urlAnalyzer';
import { analyzeMessage } from './src/utils/messageAnalyzer';

interface TestResult {
  id: string;
  category: string;
  inputSnippet: string;
  expectedVerdict: string;
  actualVerdict: string;
  actualScore: number;
  passed: boolean;
  notes: string;
}

const testResults: TestResult[] = [];

function recordTest(
  id: string,
  category: string,
  inputSnippet: string,
  expectedVerdict: string,
  actualVerdict: string,
  actualScore: number,
  condition: boolean,
  notes: string
) {
  testResults.push({
    id,
    category,
    inputSnippet,
    expectedVerdict,
    actualVerdict,
    actualScore,
    passed: condition,
    notes,
  });
}

console.log('========================================================================');
console.log('SCAMLENS SYSTEM TEST SUITE: 36 TEST CATEGORIES (16 MESSAGE + 20 URL)');
console.log('========================================================================\n');

// -----------------------------------------------------------------------------
// SECTION A: 16 MESSAGE TEST CATEGORIES
// -----------------------------------------------------------------------------

// M-1: Normal college announcement
try {
  const m1 = analyzeMessage('Hi everyone, reminder that our College Robotics Club sprint meeting will take place tomorrow at 4:30 PM in Room 302, Academic Block C. Bring project logs.');
  recordTest('MSG-01', 'Normal college announcements', m1.verdictSummary, 'SAFE', m1.verdict, m1.score, m1.verdict === 'SAFE', 'Club meeting notification');
} catch (e: any) {
  recordTest('MSG-01', 'Normal college announcements', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// M-2: Legitimate appointment reminders
try {
  const m2 = analyzeMessage('Your dentist appointment with Dr. Sharma is scheduled for tomorrow at 4:30 PM. Reply 1 to confirm or call clinic to reschedule.');
  recordTest('MSG-02', 'Legitimate appointment reminders', m2.verdictSummary, 'SAFE', m2.verdict, m2.score, m2.verdict === 'SAFE', 'Doctor clinic schedule alert');
} catch (e: any) {
  recordTest('MSG-02', 'Legitimate appointment reminders', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// M-3: Legitimate bank notification
try {
  const m3 = analyzeMessage('Your account XX1234 has been credited INR 45,000 on 24-Oct. Avail bal: INR 52,100.');
  recordTest('MSG-03', 'Legitimate bank notifications', m3.verdictSummary, 'SAFE', m3.verdict, m3.score, m3.verdict === 'SAFE', 'Routine bank credit balance update');
} catch (e: any) {
  recordTest('MSG-03', 'Legitimate bank notifications', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// M-4: Fake KYC messages
try {
  const m4 = analyzeMessage('Dear customer, your bank KYC has expired. Your netbanking access will be blocked within 24 hours. Submit documents at http://bank-kyc-update.xyz/verify immediately.');
  recordTest('MSG-04', 'Fake KYC messages', m4.verdictSummary, 'SCAM', m4.verdict, m4.score, m4.verdict === 'SCAM', 'Unverified KYC link + urgency pressure');
} catch (e: any) {
  recordTest('MSG-04', 'Fake KYC messages', '', 'SCAM', 'ERROR', -1, false, e.message);
}

// M-5: Urgent account-blocking threats
try {
  const m5 = analyzeMessage('URGENT: Your SBI account is blocked. Update KYC immediately at bit.ly/sbi-kyc or card will be permanently suspended.');
  recordTest('MSG-05', 'Urgent account-blocking threats', m5.verdictSummary, 'SCAM', m5.verdict, m5.score, m5.verdict === 'SCAM', 'Account suspension threat + shortener');
} catch (e: any) {
  recordTest('MSG-05', 'Urgent account-blocking threats', '', 'SCAM', 'ERROR', -1, false, e.message);
}

// M-6: Suspicious OTP requests
try {
  const m6 = analyzeMessage('Kindly share your O T P to reverse wrongly credited amount.');
  recordTest('MSG-06', 'Suspicious OTP requests', m6.verdictSummary, 'SCAM', m6.verdict, m6.score, m6.verdict === 'SCAM', 'Spaced credential evasion + reverse trap');
} catch (e: any) {
  recordTest('MSG-06', 'Suspicious OTP requests', '', 'SCAM', 'ERROR', -1, false, e.message);
}

// M-7: Suspicious UPI payment requests
try {
  const m7 = analyzeMessage('We mistakenly sent Rs 3,500 extra to your GPay. Open PhonePe, approve the collect request, and enter your UPI PIN to process your refund.');
  recordTest('MSG-07', 'Suspicious UPI payment requests', m7.verdictSummary, 'SCAM', m7.verdict, m7.score, m7.verdict === 'SCAM', 'UPI collect request + enter PIN trick');
} catch (e: any) {
  recordTest('MSG-07', 'Suspicious UPI payment requests', '', 'SCAM', 'ERROR', -1, false, e.message);
}

// M-8: Advance-fee job or internship offers
try {
  const m8 = analyzeMessage('Selected for Web Intern! Pay Rs 999 registration fee at link to receive laptop.');
  recordTest('MSG-08', 'Advance-fee job or internship offers', m8.verdictSummary, 'SCAM', m8.verdict, m8.score, m8.verdict === 'SCAM', 'Internship selection + upfront fee demand');
} catch (e: any) {
  recordTest('MSG-08', 'Advance-fee job or internship offers', '', 'SCAM', 'ERROR', -1, false, e.message);
}

// M-9: Unrealistic prize claims
try {
  const m9 = analyzeMessage('Congratulations! You have won Rs 25,00,000 in the Annual Lucky Draw. Claim your cash prize bonus today!');
  recordTest('MSG-09', 'Unrealistic prize claims', m9.verdictSummary, 'RISKY', m9.verdict, m9.score, m9.verdict === 'RISKY' || m9.verdict === 'SCAM', 'Unrealistic lottery / prize draw lure');
} catch (e: any) {
  recordTest('MSG-09', 'Unrealistic prize claims', '', 'RISKY', 'ERROR', -1, false, e.message);
}

// M-10: Suspicious loan offers
try {
  const m10 = analyzeMessage('Pre-approved instant cash loan of Rs 5,00,000 without documents. Pay Rs 1,200 processing fee to disburse funds to your account.');
  recordTest('MSG-10', 'Suspicious loan offers', m10.verdictSummary, 'SCAM', m10.verdict, m10.score, m10.verdict === 'SCAM' || m10.verdict === 'RISKY', 'Instant loan + advance processing fee');
} catch (e: any) {
  recordTest('MSG-10', 'Suspicious loan offers', '', 'SCAM', 'ERROR', -1, false, e.message);
}

// M-11: Urgent messages without URLs
try {
  const m11 = analyzeMessage('URGENT: Power will be disconnected tonight at 9:30 PM due to unpaid electricity bill. Contact our power officer at 9876543210 immediately.');
  recordTest('MSG-11', 'Urgent messages without URLs', m11.verdictSummary, 'RISKY/SCAM', m11.verdict, m11.score, m11.verdict === 'RISKY' || m11.verdict === 'SCAM', 'Electricity cutoff threat with personal phone');
} catch (e: any) {
  recordTest('MSG-11', 'Urgent messages without URLs', '', 'RISKY/SCAM', 'ERROR', -1, false, e.message);
}

// M-12: Suspicious messages with URLs
try {
  const m12 = analyzeMessage('India Post: Your package cannot be delivered due to incomplete address. Please update delivery address and pay Rs 25 fee at http://post-delivery.xyz/pay within 24 hours.');
  recordTest('MSG-12', 'Suspicious messages with URLs', m12.verdictSummary, 'SCAM', m12.verdict, m12.score, m12.verdict === 'SCAM', 'Courier failure + redelivery fee link');
} catch (e: any) {
  recordTest('MSG-12', 'Suspicious messages with URLs', '', 'SCAM', 'ERROR', -1, false, e.message);
}

// M-13: Legitimate messages containing words such as bank, KYC, account, and urgent
try {
  const m13 = analyzeMessage('Urgent Notice from University Finance Office: All students with scholarship accounts must verify their bank account details with the college registrar. Do not share your bank password or OTP with anyone.');
  recordTest('MSG-13', 'Legitimate message with sensitive words', m13.verdictSummary, 'SAFE', m13.verdict, m13.score, m13.verdict === 'SAFE', 'Campus advisory with defensive OTP warning');
} catch (e: any) {
  recordTest('MSG-13', 'Legitimate message with sensitive words', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// M-14: Long messages and unusual formatting
try {
  const longText = `DEPARTMENT OF COMPUTER SCIENCE & ENGINEERING
FALL SEMESTER ACADEMIC SYLLABUS & SCHEDULE

Module 1: Operating Systems & Kernel Architecture
- Process scheduling, inter-process communication, memory virtualization.
- Laboratory assignment 1 submission deadline: 15-November, 5:00 PM.

Module 2: Network Security Protocols
- TLS 1.3 cryptographic handshakes, public-key infrastructure, certificate authorities.
- Laboratory assignment 2 submission deadline: 30-November, 5:00 PM.

Notice: Attendance requirement of 75% is strictly enforced across all lecture sessions. Please check the college portal for room assignments.`;
  const m14 = analyzeMessage(longText);
  recordTest('MSG-14', 'Long message & unusual formatting', m14.verdictSummary, 'SAFE', m14.verdict, m14.score, m14.verdict === 'SAFE', 'Long syllabus text with formatting');
} catch (e: any) {
  recordTest('MSG-14', 'Long message & unusual formatting', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// M-15: Empty messages
try {
  analyzeMessage('   ');
  recordTest('MSG-15', 'Empty messages', 'Failed to throw error', 'ERROR', 'NONE', -1, false, 'Expected rejection of empty input');
} catch (e: any) {
  const pass15 = e.message.includes('Please enter or paste a message');
  recordTest('MSG-15', 'Empty messages', e.message, 'ERROR', 'ERROR', 0, pass15, 'Properly rejected empty message');
}

// M-16: Messages containing several overlapping warning signs
try {
  const m16 = analyzeMessage('Congratulations! Shortlisted for Google Internship! Urgent: Pay Rs 1,499 laptop kit fee, share your OTP for verification at http://internship-portal.xyz/pay within 2 hours or seat will be canceled.');
  recordTest('MSG-16', 'Overlapping warning signs', m16.verdictSummary, 'SCAM', m16.verdict, m16.score, m16.verdict === 'SCAM' && m16.score === 100, 'Score capped at 100 without duplicate penalty');
} catch (e: any) {
  recordTest('MSG-16', 'Overlapping warning signs', '', 'SCAM', 'ERROR', -1, false, e.message);
}

// -----------------------------------------------------------------------------
// SECTION B: 20 URL TEST CATEGORIES
// -----------------------------------------------------------------------------

// U-1: Well-known legitimate URL
try {
  const u1 = analyzeUrl('https://www.google.com');
  recordTest('URL-01', 'Well-known legitimate URL', u1.summary, 'SAFE', u1.verdict, u1.riskScore, u1.verdict === 'SAFE' && u1.riskScore === 0, 'Standard HTTPS portal');
} catch (e: any) {
  recordTest('URL-01', 'Well-known legitimate URL', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// U-2: Legitimate URL without explicit scheme
try {
  const u2 = analyzeUrl('google.com');
  recordTest('URL-02', 'URL without explicit scheme', u2.summary, 'SAFE', u2.verdict, u2.riskScore, u2.verdict === 'SAFE' && u2.protocol === 'https', 'Normalized to HTTPS');
} catch (e: any) {
  recordTest('URL-02', 'URL without explicit scheme', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// U-3: URL containing misleading subdomain
try {
  const u3 = analyzeUrl('https://sbi.co.in.scam-domain.xyz/verify');
  recordTest('URL-03', 'Misleading subdomain', u3.summary, 'SUSPICIOUS', u3.verdict, u3.riskScore, u3.verdict === 'SUSPICIOUS', 'Brand spoofing in subdomain');
} catch (e: any) {
  recordTest('URL-03', 'Misleading subdomain', '', 'SUSPICIOUS', 'ERROR', -1, false, e.message);
}

// U-4: Suspicious-looking hostname
try {
  const u4 = analyzeUrl('https://student-grant-payout-claim-reward.xyz');
  recordTest('URL-04', 'Suspicious-looking hostname', u4.summary, 'RISKY/SUSPICIOUS', u4.verdict, u4.riskScore, u4.verdict !== 'SAFE', 'Excessive hyphens + disposable TLD');
} catch (e: any) {
  recordTest('URL-04', 'Suspicious-looking hostname', '', 'RISKY/SUSPICIOUS', 'ERROR', -1, false, e.message);
}

// U-5: Suspicious path or file extension
try {
  const u5 = analyzeUrl('https://example.com/downloads/bank_update.apk');
  recordTest('URL-05', 'Suspicious file extension (.apk)', u5.summary, 'RISKY', u5.verdict, u5.riskScore, u5.verdict === 'RISKY' || u5.verdict === 'SUSPICIOUS', 'Direct .apk payload');
} catch (e: any) {
  recordTest('URL-05', 'Suspicious file extension (.apk)', '', 'RISKY', 'ERROR', -1, false, e.message);
}

// U-6: URL shortener
try {
  const u6 = analyzeUrl('https://bit.ly/student-grant');
  recordTest('URL-06', 'URL shortener', u6.summary, 'RISKY', u6.verdict, u6.riskScore, u6.verdict === 'RISKY', 'Obfuscated short destination');
} catch (e: any) {
  recordTest('URL-06', 'URL shortener', '', 'RISKY', 'ERROR', -1, false, e.message);
}

// U-7: URL using HTTP
try {
  const u7 = analyzeUrl('http://example.com');
  recordTest('URL-07', 'URL using HTTP', u7.summary, 'RISKY', u7.verdict, u7.riskScore, u7.verdict === 'RISKY', 'Unencrypted HTTP protocol');
} catch (e: any) {
  recordTest('URL-07', 'URL using HTTP', '', 'RISKY', 'ERROR', -1, false, e.message);
}

// U-8: URL using HTTPS
try {
  const u8 = analyzeUrl('https://example.com');
  recordTest('URL-08', 'URL using HTTPS', u8.summary, 'SAFE', u8.verdict, u8.riskScore, u8.verdict === 'SAFE' && u8.riskScore === 0, 'Encrypted HTTPS protocol');
} catch (e: any) {
  recordTest('URL-08', 'URL using HTTPS', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// U-9: Multipart domain such as example.co.in
try {
  const u9 = analyzeUrl('https://example.co.in');
  recordTest('URL-09', 'Multipart domain (.co.in)', u9.summary, 'SAFE', u9.verdict, u9.riskScore, u9.verdict === 'SAFE' && u9.rootDomain === 'example.co.in', 'Multi-part suffix decomposed');
} catch (e: any) {
  recordTest('URL-09', 'Multipart domain (.co.in)', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// U-10: Malformed URL
try {
  analyzeUrl('====');
  recordTest('URL-10', 'Malformed URL', 'Failed to throw error', 'ERROR', 'NONE', -1, false, 'Expected rejection of invalid host');
} catch (e: any) {
  const pass10 = e.message.includes('Malformed URL') || e.message.includes('invalid');
  recordTest('URL-10', 'Malformed URL', e.message, 'ERROR', 'ERROR', 0, pass10, 'Properly rejected malformed hostname');
}

// U-11: URL with unusual port
try {
  const u11 = analyzeUrl('https://bank-login.com:8080/portal');
  const hasPortFlag = u11.flags.some((f) => f.id === 'flag_unusual_port');
  recordTest('URL-11', 'Unusual network port (:8080)', u11.summary, 'FLAGGED', u11.verdict, u11.riskScore, hasPortFlag, 'Non-standard port detected');
} catch (e: any) {
  recordTest('URL-11', 'Unusual network port (:8080)', '', 'FLAGGED', 'ERROR', -1, false, e.message);
}

// U-12: IP-address URL
try {
  const u12 = analyzeUrl('http://192.168.1.1/login');
  recordTest('URL-12', 'Direct IP address host', u12.summary, 'SUSPICIOUS', u12.verdict, u12.riskScore, u12.verdict === 'SUSPICIOUS' && u12.isIpAddress, 'Raw IP hostname + HTTP');
} catch (e: any) {
  recordTest('URL-12', 'Direct IP address host', '', 'SUSPICIOUS', 'ERROR', -1, false, e.message);
}

// U-13: Internationalized hostname
try {
  const u13 = analyzeUrl('https://xn--e1afmkfd.xn--p1ai');
  const hasPunycode = u13.flags.some((f) => f.id === 'flag_punycode');
  recordTest('URL-13', 'Internationalized hostname', u13.summary, 'RISKY/SUSPICIOUS', u13.verdict, u13.riskScore, hasPunycode, 'Punycode IDN detected');
} catch (e: any) {
  recordTest('URL-13', 'Internationalized hostname', '', 'RISKY/SUSPICIOUS', 'ERROR', -1, false, e.message);
}

// U-14: Hostname containing punycode
try {
  const u14 = analyzeUrl('https://xn--appl-43d.com');
  const hasPunycode = u14.flags.some((f) => f.id === 'flag_punycode');
  recordTest('URL-14', 'Hostname with punycode token', u14.summary, 'RISKY/SUSPICIOUS', u14.verdict, u14.riskScore, hasPunycode, 'Punycode lookalike spoof');
} catch (e: any) {
  recordTest('URL-14', 'Hostname with punycode token', '', 'RISKY/SUSPICIOUS', 'ERROR', -1, false, e.message);
}

// U-15: URL containing query parameters and fragments
try {
  const u15 = analyzeUrl('https://example.com/portal?ref=student&token=abc#section2');
  recordTest('URL-15', 'Query parameters & fragments', u15.summary, 'SAFE', u15.verdict, u15.riskScore, u15.verdict === 'SAFE', 'Clean parsing with query params');
} catch (e: any) {
  recordTest('URL-15', 'Query parameters & fragments', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// U-16: Empty input
try {
  analyzeUrl('   ');
  recordTest('URL-16', 'Empty URL input', 'Failed to throw error', 'ERROR', 'NONE', -1, false, 'Expected rejection of empty input');
} catch (e: any) {
  const pass16 = e.message.includes('Please enter a valid website URL');
  recordTest('URL-16', 'Empty URL input', e.message, 'ERROR', 'ERROR', 0, pass16, 'Properly rejected empty URL');
}

// U-17: Dangerous schemes (javascript:, file:, data:)
try {
  let schemeRejections = 0;
  try { analyzeUrl('javascript:alert(1)'); } catch (e: any) { if (e.message.includes('javascript:')) schemeRejections++; }
  try { analyzeUrl('file:///etc/passwd'); } catch (e: any) { if (e.message.includes('file:')) schemeRejections++; }
  try { analyzeUrl('data:text/html,test'); } catch (e: any) { if (e.message.includes('data:')) schemeRejections++; }
  recordTest('URL-17', 'Dangerous schemes rejection', `${schemeRejections}/3 rejected`, 'REJECTED', 'REJECTED', 0, schemeRejections === 3, 'javascript, file, data rejected');
} catch (e: any) {
  recordTest('URL-17', 'Dangerous schemes rejection', '', 'REJECTED', 'ERROR', -1, false, e.message);
}

// U-18: Long input handling
try {
  const longUrl = 'https://example.com/' + 'a'.repeat(3000);
  const u18 = analyzeUrl(longUrl);
  recordTest('URL-18', 'Long URL input handling', u18.summary, 'SAFE', u18.verdict, u18.riskScore, u18.verdict === 'SAFE', 'Handled 3000-char path without error');
} catch (e: any) {
  recordTest('URL-18', 'Long URL input handling', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// U-19: URLs with misleading combinations of hostname and path (@ trick)
try {
  const u19 = analyzeUrl('http://paypal.com@evil-site.com');
  recordTest('URL-19', 'Misleading @ userinfo trick', u19.summary, 'SUSPICIOUS', u19.verdict, u19.riskScore, u19.verdict === 'SUSPICIOUS', 'Authority spoofing with @');
} catch (e: any) {
  recordTest('URL-19', 'Misleading @ userinfo trick', '', 'SUSPICIOUS', 'ERROR', -1, false, e.message);
}

// U-20: URLs containing common words such as login on legitimate sites
try {
  const u20 = analyzeUrl('https://accounts.google.com/signin');
  recordTest('URL-20', 'Common words on legitimate sites', u20.summary, 'SAFE', u20.verdict, u20.riskScore, u20.verdict === 'SAFE' && u20.riskScore === 0, 'No false positive on google signin');
} catch (e: any) {
  recordTest('URL-20', 'Common words on legitimate sites', '', 'SAFE', 'ERROR', -1, false, e.message);
}

// -----------------------------------------------------------------------------
// SUMMARY EXECUTION DISPLAY
// -----------------------------------------------------------------------------
let allPass = true;
let passCount = 0;

console.log('------------------------------------------------------------------------');
console.log('TEST RESULTS BY CATEGORY:');
console.log('------------------------------------------------------------------------');
for (const t of testResults) {
  const status = t.passed ? '[PASS]' : '[FAIL]';
  if (!t.passed) allPass = false;
  else passCount++;
  console.log(`${t.id} ${status} ${t.category.padEnd(42)} Expected: ${t.expectedVerdict.padEnd(14)} Actual: ${t.actualVerdict}`);
}

console.log('------------------------------------------------------------------------');
console.log(`TOTAL SUITE EXECUTION: ${passCount} / ${testResults.length} PASSED (Success Rate: ${((passCount / testResults.length) * 100).toFixed(1)}%)`);
console.log('========================================================================\n');

if (!allPass) {
  process.exit(1);
}
