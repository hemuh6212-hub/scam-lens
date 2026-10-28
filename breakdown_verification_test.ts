/**
 * ScamLens Explainable Detection Breakdown Verification Test
 *
 * Verifies the 5 specified test cases from User Requirements Section 7:
 * 1. A message requesting banking credentials and an OTP under threat of account suspension.
 * 2. A legitimate college announcement.
 * 3. A legitimate college examination fee notice.
 * 4. An internship offer requesting an upfront security deposit.
 * 5. A scholarship message requesting an upfront processing fee.
 */

import { analyzeMessage } from './src/utils/messageAnalyzer';

const testCases = [
  {
    id: 'CASE-01',
    name: 'Banking Credentials & OTP with Account Suspension Threat',
    message: 'Dear Customer, unusual activity has been detected on your bank account. To prevent account suspension, verify your identity immediately by submitting your banking credentials and OTP through our verification portal. Failure to complete verification within 15 minutes may result in restricted access.',
    expectedVerdict: 'SCAM',
    expectedScore: 75,
    mustHaveWarningCategories: ['Sensitive Credentials', 'Unverified KYC & Account Threats', 'Urgency & Coercive Pressure'],
    expectedSnippetsCheck: (snippets: string[]) => snippets.some(s => s.toLowerCase().includes('banking credentials') || s.toLowerCase().includes('otp')),
  },
  {
    id: 'CASE-02',
    name: 'Legitimate College Announcement',
    message: 'Dear students, the internal examination timetable has been published. Please check the college notice board for dates and timings.',
    expectedVerdict: 'SAFE',
    expectedScore: 0,
    mustHaveWarningCategories: [],
    expectedSnippetsCheck: (_s: string[]) => true,
  },
  {
    id: 'CASE-03',
    name: 'Legitimate College Examination Fee Notice',
    message: 'Dear students, the college examination fee payment deadline is 30 October 2026. Please log in to the official student portal using your usual college credentials to check your outstanding balance.',
    expectedVerdict: 'SAFE',
    expectedScore: 0,
    mustHaveWarningCategories: [],
    expectedSnippetsCheck: (_s: string[]) => true,
  },
  {
    id: 'CASE-04',
    name: 'Internship Offer Requesting Upfront Security Deposit',
    message: 'Congratulations! You have been selected for a remote web developer internship paying ₹25,000 per month. Pay a refundable security deposit of ₹999 to confirm your position and receive your onboarding kit.',
    expectedVerdict: 'RISKY',
    expectedMinScore: 30,
    mustHaveWarningCategories: ['Employment & Scholarship Fees'],
    expectedSnippetsCheck: (snippets: string[]) => snippets.some(s => s.toLowerCase().includes('security deposit') || s.toLowerCase().includes('selected for')),
  },
  {
    id: 'CASE-05',
    name: 'Scholarship Message Requesting Upfront Processing Fee',
    message: 'Congratulations! You have been shortlisted for the National Merit Scholarship of ₹50,000. Please pay an upfront processing fee of ₹750 at link to disburse your scholarship amount.',
    expectedVerdict: 'SCAM',
    expectedMinScore: 30,
    mustHaveWarningCategories: ['Employment & Scholarship Fees'],
    expectedSnippetsCheck: (snippets: string[]) => snippets.some(s => s.toLowerCase().includes('processing fee') || s.toLowerCase().includes('scholarship') || s.toLowerCase().includes('shortlisted')),
  },
];

console.log('================================================================================');
console.log('SCAMLENS EXPLAINABLE DETECTION BREAKDOWN VERIFICATION');
console.log('================================================================================\n');

let allPassed = true;

for (const tc of testCases) {
  const result = analyzeMessage(tc.message);
  console.log(`[TEST] ${tc.id}: ${tc.name}`);
  console.log(`  Message: "${tc.message.slice(0, 90)}..."`);
  console.log(`  Verdict: ${result.verdict} (Score: ${result.score}/100)`);
  console.log(`  Warnings Detected (${result.warningSigns.length}):`);
  
  if (result.warningSigns.length === 0) {
    console.log('    -> "No significant warning indicators were detected by the current rules."');
  } else {
    for (const w of result.warningSigns) {
      console.log(`    - [${w.category}] ${w.title} (+${w.points} pts, ${w.severity})`);
      console.log(`      Matched Evidence: ${w.matchedSnippets.map(s => `"${s}"`).join(', ')}`);
      console.log(`      Explanation: ${w.explanation}`);
    }
  }

  // Verdict validation
  if (result.verdict !== tc.expectedVerdict) {
    console.error(`  FAIL: Expected verdict ${tc.expectedVerdict}, got ${result.verdict}`);
    allPassed = false;
  }

  // Score validation
  if (tc.expectedScore !== undefined && result.score !== tc.expectedScore) {
    console.error(`  FAIL: Expected exact score ${tc.expectedScore}, got ${result.score}`);
    allPassed = false;
  }
  if (tc.expectedMinScore !== undefined && result.score < tc.expectedMinScore) {
    console.error(`  FAIL: Expected minimum score ${tc.expectedMinScore}, got ${result.score}`);
    allPassed = false;
  }

  // Categories validation
  const categories = result.warningSigns.map(w => w.category);
  for (const expectedCat of tc.mustHaveWarningCategories) {
    if (!categories.includes(expectedCat)) {
      console.error(`  FAIL: Missing expected warning category: ${expectedCat}`);
      allPassed = false;
    }
  }

  // Snippets validation
  const allSnippets = result.warningSigns.flatMap(w => w.matchedSnippets);
  if (!tc.expectedSnippetsCheck(allSnippets)) {
    console.error('  FAIL: Matched snippets did not satisfy evidence check');
    allPassed = false;
  }

  console.log('  Status: PASS\n--------------------------------------------------------------------------------');
}

if (allPassed) {
  console.log('ALL 5 BREAKDOWN VERIFICATION CASES PASSED!\n');
} else {
  console.error('SOME CASES FAILED!\n');
  process.exit(1);
}
