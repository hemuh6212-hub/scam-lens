/**
 * ScamLens Audit & Remediation Regression Test Suite
 *
 * Verifies:
 * - Critical Bug reproduction & fix
 * - Tests 1 through 10 specified in User Audit Brief
 * - Robust variations covering punctuation, capitalization, spacing, and alternative wording
 * - Legitimate controls and defensive scam advisories
 */

import { analyzeMessage } from './src/utils/messageAnalyzer';

interface TestCase {
  id: string;
  name: string;
  input: string;
  expectedVerdict: 'SAFE' | 'RISKY' | 'SCAM' | 'ERROR';
  minScore?: number;
  maxScore?: number;
  mustTriggerRules?: string[];
  mustNotTriggerRules?: string[];
  description: string;
}

const AUDIT_TESTS: TestCase[] = [
  // -------------------------------------------------------------------------
  // CORE MANDATORY TEST CASES (TESTS 1 - 10)
  // -------------------------------------------------------------------------
  {
    id: 'TEST-01',
    name: 'Critical Credential Request with Urgency and Account Threat',
    input: 'Your account will be suspended in 15 minutes. Submit your banking credentials and OTP immediately to restore access.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    mustTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_urgency'],
    description: 'Suspension threat + 15 min deadline + banking credentials and OTP request',
  },
  {
    id: 'TEST-02',
    name: 'Alternative Credential Wording',
    input: 'To prevent account closure, provide your one-time password and online banking password for verification.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    mustTriggerRules: ['rule_credentials', 'rule_kyc_verification'],
    description: 'Account closure threat + one-time password + online banking password',
  },
  {
    id: 'TEST-03',
    name: 'Suspicious KYC Message with Urgent Blocking Threat',
    input: 'URGENT: Your bank account will be blocked today. Complete your KYC using this verification link immediately.',
    expectedVerdict: 'RISKY',
    minScore: 25,
    mustTriggerRules: ['rule_kyc_verification', 'rule_urgency'],
    description: 'Bank account blocking threat + KYC prompt + verification link + urgency',
  },
  {
    id: 'TEST-04',
    name: 'Advance-Fee Remote Internship Offer',
    input: 'You have been selected for a remote internship paying ₹25,000 per month. Pay a refundable security deposit of ₹799 to confirm your position.',
    expectedVerdict: 'RISKY',
    minScore: 30,
    mustTriggerRules: ['rule_job_fee'],
    description: 'Upfront deposit requested for guaranteed internship position',
  },
  {
    id: 'TEST-05',
    name: 'Ordinary College Announcement',
    input: 'Dear students, the internal examination timetable has been published. Please check the college notice board for dates and timings.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_urgency', 'rule_job_fee'],
    description: 'Standard benign academic announcement with zero fraud indicators',
  },
  {
    id: 'TEST-06',
    name: 'Legitimate Examination Fee Notice with Portal Login Advice',
    input: 'Dear students, the college examination fee payment deadline is 30 October 2026. Please log in to the official student portal using your usual college credentials to check your outstanding balance.',
    expectedVerdict: 'SAFE',
    maxScore: 10,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification'],
    description: 'Benign fee reminder directing to official portal with college credentials',
  },
  {
    id: 'TEST-07',
    name: 'Ordinary Payment Confirmation',
    input: 'Your payment of ₹250 was successful. Please check your payment application for the receipt.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    mustNotTriggerRules: ['rule_credentials', 'rule_upi_collect_refund', 'rule_job_fee'],
    description: 'Standard payment confirmation receipt notification',
  },
  {
    id: 'TEST-08',
    name: 'Urgent But Legitimate Academic Notice',
    input: 'Reminder: Submit your college assignment before 5 PM today. Contact your lecturer if you need assistance.',
    expectedVerdict: 'SAFE',
    maxScore: 10,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification'],
    description: 'Coursework deadline reminder with no financial or credential demands',
  },
  {
    id: 'TEST-09',
    name: 'Multiple Critical Indicators Combined',
    input: 'Your account will be blocked immediately. Click this verification link and submit your OTP and ATM PIN within 10 minutes.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    mustTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_urgency'],
    description: 'Immediate block threat + verification link + OTP + ATM PIN + 10 min countdown',
  },
  {
    id: 'TEST-10',
    name: 'Empty Input Validation',
    input: '   ',
    expectedVerdict: 'ERROR',
    description: 'Engine should reject whitespace-only or empty strings safely',
  },

  // -------------------------------------------------------------------------
  // AUDIT SPECIFIC & VARIATION TEST CASES
  // -------------------------------------------------------------------------
  {
    id: 'TEST-11',
    name: 'Original Reported Bug Reproduction',
    input: 'Dear Customer, unusual activity has been detected on your bank account. To prevent account suspension, verify your identity immediately by submitting your banking credentials and OTP through our verification portal. Failure to complete verification within 15 minutes may result in restricted access.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    mustTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_urgency'],
    description: 'Exact message reported by user that previously scored 15/100 SAFE',
  },
  {
    id: 'TEST-12',
    name: 'Punctuation Obfuscated Credentials in Threat Context',
    input: 'Security Alert: Unusual activity detected on account. Submit your O.T.P and A.T.M P-I-N immediately to avoid access restriction.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    mustTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_urgency'],
    description: 'De-obfuscated dots/dashes in OTP and ATM PIN with unusual activity and restriction threats',
  },
  {
    id: 'TEST-13',
    name: 'Capitalization & Aggressive Case Variation',
    input: 'URGENT NOTICE: YOUR ACCOUNT HAS BEEN FLAGGED FOR SUSPENSION. SUBMIT YOUR BANKING CREDENTIALS AND ONE-TIME PASSWORD IN 15 MINUTES.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    mustTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_urgency'],
    description: 'All-uppercase message with suspension threat and banking credentials demand',
  },
  {
    id: 'TEST-14',
    name: 'CVV and Card Security Code Solicitation',
    input: 'Your debit card access has been restricted. Please provide your 3-digit CVV and card security code at the verification portal.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    mustTriggerRules: ['rule_credentials', 'rule_kyc_verification'],
    description: 'Restricted card claim combined with CVV / card security code solicitation',
  },
  {
    id: 'TEST-15',
    name: 'Legitimate Defensive Advisory Mentioning Credentials',
    input: 'Security Advisory: Fraudsters may ask you to submit your OTP, PIN, or banking credentials. Never disclose or share your password with anyone.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    mustNotTriggerRules: ['rule_credentials'],
    description: 'Defensive awareness advisory warning users NEVER to share credentials',
  },
  {
    id: 'TEST-16',
    name: 'Legitimate Urgent Campus Advisory',
    input: 'Urgent notice: Due to severe weather forecasts, all evening classes after 4 PM today are cancelled. Please travel home safely.',
    expectedVerdict: 'SAFE',
    maxScore: 20,
    mustNotTriggerRules: ['rule_credentials', 'rule_kyc_verification', 'rule_job_fee'],
    description: 'Weather advisory containing urgency word without financial/credential hooks',
  },
];

console.log('================================================================================');
console.log('SCAMLENS AUDIT & REMEDIATION REGRESSION TEST SUITE');
console.log('Testing User Mandated Cases 1-10, Bug Reproduction, and Linguistic Variations');
console.log('================================================================================\n');

let passedCount = 0;
let failedCount = 0;

for (const test of AUDIT_TESTS) {
  let passed = true;
  const failureReasons: string[] = [];

  if (test.expectedVerdict === 'ERROR') {
    try {
      analyzeMessage(test.input);
      passed = false;
      failureReasons.push('Expected engine to throw an error for empty input, but it returned a result.');
    } catch {
      passed = true;
    }
    console.log(`[${passed ? 'PASS' : 'FAIL'}] [${test.id}] ${test.name}`);
    if (!passed) {
      console.log(`       Failures: ${failureReasons.join('; ')}`);
      failedCount++;
    } else {
      passedCount++;
    }
    console.log('--------------------------------------------------------------------------------');
    continue;
  }

  try {
    const result = analyzeMessage(test.input);
    const triggeredRules = result.warningSigns.map((w) => w.id);

    // 1. Check verdict
    if (result.verdict !== test.expectedVerdict) {
      passed = false;
      failureReasons.push(`Expected verdict ${test.expectedVerdict} but got ${result.verdict}`);
    }

    // 2. Check min score
    if (test.minScore !== undefined && result.score < test.minScore) {
      passed = false;
      failureReasons.push(`Expected minimum score ${test.minScore} but got ${result.score}`);
    }

    // 3. Check max score
    if (test.maxScore !== undefined && result.score > test.maxScore) {
      passed = false;
      failureReasons.push(`Expected maximum score ${test.maxScore} but got ${result.score}`);
    }

    // 4. Check mustTriggerRules
    if (test.mustTriggerRules) {
      for (const ruleId of test.mustTriggerRules) {
        if (!triggeredRules.includes(ruleId)) {
          passed = false;
          failureReasons.push(`Expected rule "${ruleId}" to trigger, but it was not triggered`);
        }
      }
    }

    // 5. Check mustNotTriggerRules
    if (test.mustNotTriggerRules) {
      for (const ruleId of test.mustNotTriggerRules) {
        if (triggeredRules.includes(ruleId)) {
          passed = false;
          failureReasons.push(`Rule "${ruleId}" triggered unexpectedly`);
        }
      }
    }

    console.log(`[${passed ? 'PASS' : 'FAIL'}] [${test.id}] ${test.name}`);
    console.log(`       Input:   "${test.input.slice(0, 85)}${test.input.length > 85 ? '...' : ''}"`);
    console.log(`       Verdict: ${result.verdict} (Score: ${result.score}/100) | Flags: ${triggeredRules.join(', ') || 'None'}`);

    if (!passed) {
      console.log(`       Failures: ${failureReasons.join('; ')}`);
      failedCount++;
    } else {
      passedCount++;
    }
  } catch (err: unknown) {
    passed = false;
    const msg = err instanceof Error ? err.message : String(err);
    console.log(`[FAIL] [${test.id}] ${test.name}`);
    console.log(`       Exception thrown: ${msg}`);
    failedCount++;
  }

  console.log('--------------------------------------------------------------------------------');
}

console.log(`\nAUDIT SUITE SUMMARY: ${passedCount} / ${AUDIT_TESTS.length} PASSED (${failedCount} failed)`);
if (failedCount === 0) {
  console.log('All mandatory audit test cases and variation tests PASSED perfectly!\n');
} else {
  console.log('Some audit test cases FAILED.\n');
  process.exit(1);
}
