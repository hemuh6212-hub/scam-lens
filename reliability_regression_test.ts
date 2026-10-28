/**
 * ScamLens Detection Reliability Regression Test Suite
 *
 * Evaluates core reliability cases A through F as specified in Step 4:
 * A. Demanding banking credentials and OTP under threat of account suspension -> High Risk (SCAM)
 * B. Ordinary college announcement with no suspicious indicators -> Low Risk (SAFE)
 * C. Legitimate college examination-fee notice -> Not classified as a scam (SAFE)
 * D. Internship offering high salary while demanding refundable onboarding deposit -> Elevated Risk (RISKY/SCAM)
 * E. Scholarship message requesting an upfront processing fee -> Elevated Risk (RISKY/SCAM)
 * F. Messages containing isolated words such as "bank", "fee", or "urgent" -> Not classified as a scam (SAFE)
 */

import { analyzeMessage } from './src/utils/messageAnalyzer';

interface TestCase {
  id: string;
  category: 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
  description: string;
  message: string;
  expectedVerdict: 'SAFE' | 'RISKY' | 'SCAM';
  minScore?: number;
  maxScore?: number;
  mustTriggerRules?: string[];
  mustNotTriggerRules?: string[];
}

const TEST_CASES: TestCase[] = [
  // ---------------------------------------------------------------------------
  // CASE A: Credential Demand + Account Suspension Threat (High Risk / SCAM)
  // ---------------------------------------------------------------------------
  {
    id: 'CASE-A1',
    category: 'A',
    description: 'Banking credentials & OTP demand under 15-minute suspension threat',
    message: 'Dear Customer, unusual activity has been detected on your bank account. To prevent account suspension, verify your identity immediately by submitting your banking credentials and OTP through our verification portal. Failure to complete verification within 15 minutes may result in restricted access.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    mustTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_urgency'],
  },
  {
    id: 'CASE-A2',
    category: 'A',
    description: 'Suspension threat with 10-minute countdown and OTP/credentials demand',
    message: 'ALERT: Your netbanking account has been flagged for suspension. Submit your banking credentials and 6-digit OTP within 10 minutes to avoid access termination.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    mustTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_urgency'],
  },
  {
    id: 'CASE-A3',
    category: 'A',
    description: 'Account block threat with immediate password & OTP solicitation',
    message: 'Account Security Notice: Immediate action required. Your account will be blocked today. Please provide your online banking password and one-time password to restore access.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    mustTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_urgency'],
  },

  // ---------------------------------------------------------------------------
  // CASE B: Ordinary College Announcements (Low Risk / SAFE)
  // ---------------------------------------------------------------------------
  {
    id: 'CASE-B1',
    category: 'B',
    description: 'Campus closure notice for library maintenance',
    message: 'Dear students, the college campus will remain closed on Monday for library maintenance. Regular classes will resume on Tuesday.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee', 'rule_urgency'],
  },
  {
    id: 'CASE-B2',
    category: 'B',
    description: 'Engineering department workshop announcement',
    message: 'Department Notice: The workshop on Embedded Systems is scheduled for Friday at 10 AM in Lab 3. All registered students are requested to attend.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee', 'rule_urgency'],
  },
  {
    id: 'CASE-B3',
    category: 'B',
    description: 'Annual college sports committee tournament announcement',
    message: 'College Sports Committee: Trials for the annual inter-college basketball tournament will be held on the main grounds this Saturday at 8 AM.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee', 'rule_urgency'],
  },

  // ---------------------------------------------------------------------------
  // CASE C: Legitimate College Examination Fee Notices (Not a scam / SAFE)
  // ---------------------------------------------------------------------------
  {
    id: 'CASE-C1',
    category: 'C',
    description: 'Exam fee deadline with official student portal login instructions',
    message: 'Dear students, the college examination fee payment deadline is 30 October 2026. Please log in to the official student portal using your usual college credentials to check your outstanding balance.',
    expectedVerdict: 'SAFE',
    maxScore: 10,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee'],
  },
  {
    id: 'CASE-C2',
    category: 'C',
    description: 'Semester regular examination fee payment notice via accounts counter/ERP',
    message: 'Academic Notice: Regular examination fee for 5th semester is due by 15th November. Pay at the college accounts counter or through the official college ERP portal.',
    expectedVerdict: 'SAFE',
    maxScore: 10,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee'],
  },
  {
    id: 'CASE-C3',
    category: 'C',
    description: 'Final year supplementary exam fee notice on university website',
    message: 'Notice to Final Year Students: Supplementary examination fee submission is now open on the official university website until next Friday at 5 PM.',
    expectedVerdict: 'SAFE',
    maxScore: 10,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee'],
  },

  // ---------------------------------------------------------------------------
  // CASE D: Internship Offer with Refundable Deposit (Elevated Risk / RISKY or SCAM)
  // ---------------------------------------------------------------------------
  {
    id: 'CASE-D1',
    category: 'D',
    description: 'High salary remote internship demanding refundable onboarding deposit',
    message: 'Congratulations! You have been selected for a remote web developer internship paying ₹35,000 per month. Please pay a refundable onboarding deposit of ₹999 to receive your work laptop and developer credentials.',
    expectedVerdict: 'RISKY',
    minScore: 30,
    mustTriggerRules: ['rule_job_fee'],
  },
  {
    id: 'CASE-D2',
    category: 'D',
    description: 'Shortlisted candidate asked for refundable security deposit for onboarding kit',
    message: 'Summer Internship Offer: You are shortlisted for data analyst role (Stipend: ₹30,000/mo). A refundable security deposit of ₹1,200 is required for your onboarding kit.',
    expectedVerdict: 'RISKY',
    minScore: 30,
    mustTriggerRules: ['rule_job_fee'],
  },
  {
    id: 'CASE-D3',
    category: 'D',
    description: 'Content specialist internship requiring registration fee for training slot',
    message: 'Work from home internship: Selected as content specialist earning ₹25,000 monthly. Transfer ₹799 registration fee to confirm your training slot.',
    expectedVerdict: 'RISKY',
    minScore: 30,
    mustTriggerRules: ['rule_job_fee'],
  },

  // ---------------------------------------------------------------------------
  // CASE E: Scholarship Message Requesting Upfront Processing Fee (Elevated Risk / RISKY or SCAM)
  // ---------------------------------------------------------------------------
  {
    id: 'CASE-E1',
    category: 'E',
    description: 'National scholarship award demanding upfront documentation & processing fee',
    message: 'National Student Scholarship: You have been awarded a grant of ₹50,000. Pay an upfront documentation and processing fee of ₹650 at http://scholarship-portal.xyz to disburse your funds.',
    expectedVerdict: 'RISKY',
    minScore: 30,
    mustTriggerRules: ['rule_job_fee'],
  },
  {
    id: 'CASE-E2',
    category: 'E',
    description: 'Shortlisted scholarship requiring upfront disbursement fee',
    message: 'Higher Education Merit Scholarship: You are shortlisted for ₹40,000 award. Please pay an upfront disbursement fee of ₹500 to release the sanction amount.',
    expectedVerdict: 'RISKY',
    minScore: 30,
    mustTriggerRules: ['rule_job_fee'],
  },
  {
    id: 'CASE-E3',
    category: 'E',
    description: 'Research fellowship demanding processing charge for fund disbursement',
    message: 'State Fellowship Award: Selected for research grant of ₹60,000. Pay ₹850 processing charge to activate scholarship disbursement.',
    expectedVerdict: 'RISKY',
    minScore: 30,
    mustTriggerRules: ['rule_job_fee'],
  },

  // ---------------------------------------------------------------------------
  // CASE F: Isolated Words "bank", "fee", or "urgent" (Not a scam / SAFE)
  // ---------------------------------------------------------------------------
  {
    id: 'CASE-F1',
    category: 'F',
    description: 'Message containing isolated word "bank" in routine campus context',
    message: 'Please visit the college bank branch on campus to collect your student debit card during office hours.',
    expectedVerdict: 'SAFE',
    maxScore: 15,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification'],
  },
  {
    id: 'CASE-F2',
    category: 'F',
    description: 'Message containing isolated word "fee" for semester receipt collection',
    message: 'Tuition fee receipts for the spring semester can be collected from the administrative office.',
    expectedVerdict: 'SAFE',
    maxScore: 15,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee'],
  },
  {
    id: 'CASE-F3',
    category: 'F',
    description: 'Message containing isolated word "urgent" for cafeteria schedule change',
    message: 'Urgent notice: The campus cafeteria will close at 3 PM today due to scheduled kitchen repairs.',
    expectedVerdict: 'SAFE',
    maxScore: 20,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee'],
  },
  {
    id: 'CASE-F4',
    category: 'F',
    description: 'Message containing isolated words "bank" and "scholarship" without fee demand',
    message: 'Reminder: Contact your bank branch if you need an official statement for your government scholarship application verification.',
    expectedVerdict: 'SAFE',
    maxScore: 15,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee'],
  },
  {
    id: 'CASE-F5',
    category: 'F',
    description: 'Message containing isolated word "fee" for campus transportation counter',
    message: 'The college bus fee counter on the ground floor will remain open until 4 PM.',
    expectedVerdict: 'SAFE',
    maxScore: 15,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee'],
  },
];

console.log('================================================================================');
console.log('SCAMLENS DETECTION RELIABILITY REGRESSION TEST SUITE');
console.log('Testing Cases A through F and Realistic Context Variations');
console.log('================================================================================\n');

let passedCount = 0;
let failedCount = 0;

for (const tc of TEST_CASES) {
  let casePassed = true;
  const failureReasons: string[] = [];

  const result = analyzeMessage(tc.message);
  const triggeredRules = result.warningSigns.map((w) => w.id);

  // Verdict check (for elevated cases D and E, either RISKY or SCAM is acceptable if minScore met)
  if (tc.category === 'D' || tc.category === 'E') {
    if (result.verdict === 'SAFE') {
      casePassed = false;
      failureReasons.push(`Expected elevated risk (RISKY or SCAM) but got SAFE (${result.score} pts)`);
    }
  } else if (result.verdict !== tc.expectedVerdict) {
    casePassed = false;
    failureReasons.push(`Expected verdict ${tc.expectedVerdict} but got ${result.verdict}`);
  }

  // Min score check
  if (tc.minScore !== undefined && result.score < tc.minScore) {
    casePassed = false;
    failureReasons.push(`Expected min score ${tc.minScore} but got ${result.score}`);
  }

  // Max score check
  if (tc.maxScore !== undefined && result.score > tc.maxScore) {
    casePassed = false;
    failureReasons.push(`Expected max score ${tc.maxScore} but got ${result.score}`);
  }

  // Must trigger rules
  if (tc.mustTriggerRules) {
    for (const ruleId of tc.mustTriggerRules) {
      if (!triggeredRules.includes(ruleId)) {
        casePassed = false;
        failureReasons.push(`Expected rule "${ruleId}" to trigger, but it did not`);
      }
    }
  }

  // Must not trigger rules
  if (tc.mustNotTriggerRules) {
    for (const ruleId of tc.mustNotTriggerRules) {
      if (triggeredRules.includes(ruleId)) {
        casePassed = false;
        failureReasons.push(`Rule "${ruleId}" triggered unexpectedly`);
      }
    }
  }

  console.log(`[${casePassed ? 'PASS' : 'FAIL'}] [CASE-${tc.category}] ${tc.id}: ${tc.description}`);
  console.log(`       Verdict: ${result.verdict} (Score: ${result.score}/100) | Flags: ${triggeredRules.join(', ') || 'None'}`);

  if (!casePassed) {
    console.log(`       Failures: ${failureReasons.join('; ')}`);
    failedCount++;
  } else {
    passedCount++;
  }
  console.log('--------------------------------------------------------------------------------');
}

console.log(`\nRELIABILITY SUITE SUMMARY: ${passedCount} / ${TEST_CASES.length} PASSED (${failedCount} failed)`);
if (failedCount === 0) {
  console.log('All reliability test cases A through F PASSED successfully!\n');
} else {
  console.log('Some reliability test cases FAILED.\n');
  process.exit(1);
}
