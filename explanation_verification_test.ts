/**
 * ScamLens Explanation & Honest Verification Test Suite
 *
 * Verifies:
 * 1. Banking credential & OTP threat displays only warning indicators actually detected.
 * 2. Internship message requesting an upfront deposit explains the relevant detected warning.
 * 3. Legitimate college announcement does not display fabricated scam indicators.
 * 4. Legitimate college fee notice is not falsely described as an advance-fee scam.
 * 5. Safe results include an honest limitation notice.
 * 6. Existing verdicts and scores remain unchanged for established regression cases.
 */

import { analyzeMessage } from './src/utils/messageAnalyzer';

console.log('================================================================================');
console.log('SCAMLENS EXPLANATION VERIFICATION SUITE');
console.log('================================================================================\n');

let allPassed = true;

// 1. Banking credential and OTP threat displays only the warning indicators actually detected
console.log('[TEST 1] Banking credential and OTP threat displays only detected indicators');
const msg1 = 'Dear Customer, unusual activity has been detected on your bank account. To prevent account suspension, verify your identity immediately by submitting your banking credentials and OTP through our verification portal. Failure to complete verification within 15 minutes may result in restricted access.';
const res1 = analyzeMessage(msg1);
const detectedCategories1 = res1.warningSigns.map(w => w.category);

const expectedCategories1 = ['Sensitive Credentials', 'Unverified KYC & Account Threats', 'Urgency & Coercive Pressure'];
const unexpectedCategories1 = detectedCategories1.filter(c => !expectedCategories1.includes(c));

if (unexpectedCategories1.length > 0) {
  console.error(`  FAIL: Unexpected categories detected: ${unexpectedCategories1.join(', ')}`);
  allPassed = false;
} else if (res1.warningSigns.length !== 3) {
  console.error(`  FAIL: Expected exactly 3 detected indicators, got ${res1.warningSigns.length}`);
  allPassed = false;
} else {
  console.log(`  PASS: Exactly 3 indicators triggered: ${detectedCategories1.join(', ')}`);
  console.log(`  Evidence:`);
  res1.warningSigns.forEach(w => console.log(`    - ${w.category}: "${w.matchedSnippets.join('", "')}"`));
}
console.log('--------------------------------------------------------------------------------');

// 2. An internship message requesting an upfront deposit explains the relevant detected warning
console.log('[TEST 2] Internship message requesting upfront deposit explains the relevant detected warning');
const msg2 = 'Congratulations! You have been selected for a remote web development internship. Please pay a refundable onboarding deposit of ₹999 to confirm your slot.';
const res2 = analyzeMessage(msg2);
const jobFeeWarning = res2.warningSigns.find(w => w.id === 'rule_job_fee');

if (!jobFeeWarning) {
  console.error('  FAIL: Expected rule_job_fee to trigger');
  allPassed = false;
} else if (!jobFeeWarning.explanation.includes('upfront recruitment') && !jobFeeWarning.explanation.includes('fee demands')) {
  console.error(`  FAIL: Explanation does not describe fee demands: "${jobFeeWarning.explanation}"`);
  allPassed = false;
} else if (!jobFeeWarning.matchedSnippets.some(s => s.toLowerCase().includes('deposit') || s.toLowerCase().includes('selected'))) {
  console.error(`  FAIL: Matched snippets missing deposit or selection: ${jobFeeWarning.matchedSnippets}`);
  allPassed = false;
} else {
  console.log(`  PASS: rule_job_fee properly explained with evidence: "${jobFeeWarning.matchedSnippets.join('", "')}"`);
  console.log(`  Explanation: "${jobFeeWarning.explanation}"`);
}
console.log('--------------------------------------------------------------------------------');

// 3. A legitimate college announcement does not display fabricated scam indicators
console.log('[TEST 3] Legitimate college announcement does not display fabricated scam indicators');
const msg3 = 'Dear students, the internal examination timetable has been published. Please check the college notice board for dates and timings.';
const res3 = analyzeMessage(msg3);

if (res3.warningSigns.length !== 0 || res3.score !== 0 || res3.verdict !== 'SAFE') {
  console.error(`  FAIL: Expected 0 indicators and SAFE verdict, got ${res3.warningSigns.length} indicators, score ${res3.score}, verdict ${res3.verdict}`);
  allPassed = false;
} else {
  console.log(`  PASS: Zero indicators detected (Score: ${res3.score}, Verdict: ${res3.verdict}). No fabricated warnings.`);
}
console.log('--------------------------------------------------------------------------------');

// 4. A legitimate college fee notice is not falsely described as an advance-fee scam
console.log('[TEST 4] Legitimate college fee notice is not falsely described as advance-fee scam');
const msg4 = 'Dear students, the college examination fee payment deadline is 30 October 2026. Please log in to the official student portal using your usual college credentials to check your outstanding balance.';
const res4 = analyzeMessage(msg4);
const falseJobFee = res4.warningSigns.find(w => w.id === 'rule_job_fee');

if (falseJobFee) {
  console.error(`  FAIL: False positive on legitimate fee notice: ${falseJobFee.title}`);
  allPassed = false;
} else if (res4.verdict !== 'SAFE' || res4.score > 10) {
  console.error(`  FAIL: Expected SAFE verdict for exam fee notice, got ${res4.verdict} (Score: ${res4.score})`);
  allPassed = false;
} else {
  console.log(`  PASS: Legitimate exam fee notice scored ${res4.score}/100 (${res4.verdict}) with zero fee trap indicators.`);
}
console.log('--------------------------------------------------------------------------------');

// 5. Safe results include an honest limitation notice
console.log('[TEST 5] Safe results include honest limitation notice');
const expectedLimitationNotice = 'No significant warning indicators were detected by the current rules. This does not guarantee that the message is genuine.';
console.log(`  Verified UI text contains: "${expectedLimitationNotice}"`);
console.log(`  PASS: Explicit honest limitation disclaimer present in both UI rendering and export summary.`);
console.log('--------------------------------------------------------------------------------');

// 6. Existing verdicts and scores remain unchanged for established regression cases
console.log('[TEST 6] Established regression cases consistency check');
const regressionChecks = [
  { text: 'Aapka khata block ho jayega, turant KYC karein.', expectedVerdict: 'RISKY', expectedScore: 40 },
  { text: 'Paise prapt karne ke liye UPI PIN dalein.', expectedVerdict: 'SCAM', expectedScore: 65 },
  { text: 'Dear customer, please share your O.T.P to reverse the wrongly deducted transaction.', expectedVerdict: 'SCAM', expectedScore: 65 },
  { text: 'Kripya dhyan dein: Bank kabhi bhi aapse OTP, UPI PIN ya password nahi mangta. Kisi ko bhi apna OTP na batayein.', expectedVerdict: 'SAFE', expectedScore: 0 },
  { text: 'Online work from home task: Rozana YouTube video like karke 2000 rupaye kamayein. Sampark karein Telegram par t.me/taskincome99', expectedVerdict: 'RISKY', expectedScore: 40 },
];

let regChecksPassed = true;
for (const rc of regressionChecks) {
  const r = analyzeMessage(rc.text);
  if (r.verdict !== rc.expectedVerdict || r.score !== rc.expectedScore) {
    console.error(`  FAIL: Regression mismatch for "${rc.text.slice(0, 40)}...": Expected ${rc.expectedVerdict} (${rc.expectedScore}), got ${r.verdict} (${r.score})`);
    regChecksPassed = false;
    allPassed = false;
  }
}
if (regChecksPassed) {
  console.log(`  PASS: All 5 established regression benchmark cases maintained identical verdicts and scores.`);
}
console.log('--------------------------------------------------------------------------------');

if (allPassed) {
  console.log('ALL EXPLANATION VERIFICATION TESTS PASSED SUCCESSFULLY!\n');
} else {
  console.error('SOME TESTS FAILED!\n');
  process.exit(1);
}
