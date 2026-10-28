/**
 * ScamLens Phase 4 Corrections Regression Test Suite
 *
 * Verifies:
 * 1. Reproductions of both Phase 4 false negatives:
 *    - Hinglish video-liking task scam with Telegram redirection
 *    - Intervening modifier ("6-digit") in credential request
 * 2. Multiple variations of each false-negative pattern:
 *    - Variations of task scams (video liking, daily earnings in Hinglish, Telegram/WhatsApp redirection)
 *    - Variations of credential requests (4-digit PIN, 4-digit UPI PIN, temporary password, 3-digit CVV, 6-digit OTP)
 * 3. Legitimate control messages to ensure zero false positives:
 *    - Work from home policy notice
 *    - YouTube college video sharing
 *    - Casual request to like a friend's video
 *    - Official university study group Telegram link (isolated single low-risk signal)
 *    - Legitimate OTP delivery message mentioning "6-digit OTP"
 *    - Defensive bank security advisory mentioning "6-digit OTP" and "4-digit PIN"
 */

import { analyzeMessage } from './src/utils/messageAnalyzer';

interface RegressionCase {
  id: string;
  category: string;
  description: string;
  message: string;
  expectedVerdict: 'SAFE' | 'RISKY' | 'SCAM';
  expectedMinScore?: number;
  expectedMaxScore?: number;
  mustTriggerFlags?: string[];
  mustNotTriggerFlags?: string[];
}

export const REGRESSION_CASES: RegressionCase[] = [
  // ---------------------------------------------------------------------------
  // 1. REPRODUCTIONS OF PHASE 4 FALSE NEGATIVES
  // ---------------------------------------------------------------------------
  {
    id: 'REG-FN-01',
    category: 'Phase 4 FN 1: Hinglish Task Scam',
    description: 'Exact Phase 4 case HIN-NEW-04 (video like karke ... rupaye kamayein + Telegram)',
    message: 'Online work from home task: Rozana YouTube video like karke 2000 rupaye kamayein. Sampark karein Telegram par t.me/taskincome99',
    expectedVerdict: 'RISKY',
    expectedMinScore: 40,
    mustTriggerFlags: ['rule_unrealistic_rewards', 'rule_off_platform_redirection'],
  },
  {
    id: 'REG-FN-02',
    category: 'Phase 4 FN 2: Intervening Modifier Credential Request',
    description: 'Exact Phase 4 case OBF-NEW-01 ("forward the 6-digit O*T*P")',
    message: 'Verification alert: Please forward the 6-digit O*T*P received on your mobile to complete authorization.',
    expectedVerdict: 'RISKY',
    expectedMinScore: 35,
    mustTriggerFlags: ['rule_credentials'],
  },

  // ---------------------------------------------------------------------------
  // 2. VARIATIONS OF HINGLISH TASK SCAMS
  // ---------------------------------------------------------------------------
  {
    id: 'REG-TASK-01',
    category: 'Hinglish Task Scam Variations',
    description: 'Ghar baithe video like karke paise kamayein + Telegram',
    message: 'Ghar baithe YouTube video like karke paise kamayein, sampark karein Telegram par t.me/earnfastdaily',
    expectedVerdict: 'RISKY',
    expectedMinScore: 40,
    mustTriggerFlags: ['rule_unrealistic_rewards', 'rule_off_platform_redirection'],
  },
  {
    id: 'REG-TASK-02',
    category: 'Hinglish Task Scam Variations',
    description: 'Daily task complete karke rupaye kamayein',
    message: 'Part-time online task complete karke 1500 rupaye kamayein rozana. Contact on WhatsApp: wa.me/919988776655',
    expectedVerdict: 'RISKY',
    expectedMinScore: 40,
    mustTriggerFlags: ['rule_unrealistic_rewards', 'rule_off_platform_redirection'],
  },
  {
    id: 'REG-TASK-03',
    category: 'Hinglish Task Scam Variations',
    description: 'YouTube channel subscribe karke daily earning promise with phishing URL',
    message: 'Rozana 2000 rupaye kamayein YouTube channel subscribe karke. Register now at http://youtube-earning.xyz/start',
    expectedVerdict: 'RISKY',
    expectedMinScore: 50,
    mustTriggerFlags: ['rule_unrealistic_rewards', 'rule_suspicious_urls'],
  },
  {
    id: 'REG-TASK-04',
    category: 'Hinglish Task Scam Variations',
    description: 'Instagram posts like karke daily earnings',
    message: 'Easy work from home task: Instagram posts like karke har din 1000 se 3000 rupaye kamayein bina kisi investment ke.',
    expectedVerdict: 'RISKY',
    expectedMinScore: 25,
    mustTriggerFlags: ['rule_unrealistic_rewards'],
  },

  // ---------------------------------------------------------------------------
  // 3. VARIATIONS OF CREDENTIAL REQUESTS WITH MODIFIERS
  // ---------------------------------------------------------------------------
  {
    id: 'REG-CRED-01',
    category: 'Credential Modifier Variations',
    description: 'Share your 4-digit PIN in refund lure',
    message: 'Dear customer, kindly share your 4-digit PIN with our executive to reverse the wrongly deducted transaction.',
    expectedVerdict: 'SCAM',
    expectedMinScore: 65,
    mustTriggerFlags: ['rule_credentials', 'rule_upi_collect_refund'],
  },
  {
    id: 'REG-CRED-02',
    category: 'Credential Modifier Variations',
    description: 'Enter your 4-digit UPI PIN to claim reward',
    message: 'Congratulations! You won cashback. Enter your 4-digit UPI PIN to claim the prize.',
    expectedVerdict: 'SCAM',
    expectedMinScore: 60,
    mustTriggerFlags: ['rule_credentials', 'rule_unrealistic_rewards'],
  },
  {
    id: 'REG-CRED-03',
    category: 'Credential Modifier Variations',
    description: 'Forward us your temporary password',
    message: 'Important security reset: Forward to us your temporary password received on your email.',
    expectedVerdict: 'RISKY',
    expectedMinScore: 35,
    mustTriggerFlags: ['rule_credentials'],
  },
  {
    id: 'REG-CRED-04',
    category: 'Credential Modifier Variations',
    description: 'Tell our agent the 6-digit OTP with account threat',
    message: 'Urgent: Tell our support agent the 6-digit OTP immediately or your netbanking account will be blocked.',
    expectedVerdict: 'SCAM',
    expectedMinScore: 65,
    mustTriggerFlags: ['rule_credentials', 'rule_kyc_verification', 'rule_urgency'],
  },
  {
    id: 'REG-CRED-05',
    category: 'Credential Modifier Variations',
    description: 'Provide the 3-digit CVV on back of card with card blocking threat',
    message: 'Your debit card will be permanently blocked. Provide the 3-digit CVV and card expiry to unfreeze netbanking.',
    expectedVerdict: 'SCAM',
    expectedMinScore: 60,
    mustTriggerFlags: ['rule_credentials', 'rule_kyc_verification'],
  },
  {
    id: 'REG-CRED-06',
    category: 'Credential Modifier Variations',
    description: 'Hinglish apna 6-digit OTP batayein',
    message: 'Aapka transaction hold par hai. Kripya apna 6-digit OTP batayein transaction release karne ke liye.',
    expectedVerdict: 'RISKY',
    expectedMinScore: 35,
    mustTriggerFlags: ['rule_credentials'],
  },

  // ---------------------------------------------------------------------------
  // 4. LEGITIMATE CONTROLS & FALSE-POSITIVE PREVENTION
  // ---------------------------------------------------------------------------
  {
    id: 'REG-CTRL-01',
    category: 'Legitimate Control',
    description: 'Work from home corporate policy update (contains "work from home")',
    message: 'Work from home policy update: All engineering team members should join Monday standup at 10 AM on Zoom.',
    expectedVerdict: 'SAFE',
    expectedMaxScore: 0,
    mustNotTriggerFlags: ['rule_unrealistic_rewards', 'rule_job_fee'],
  },
  {
    id: 'REG-CTRL-02',
    category: 'Legitimate Control',
    description: 'College presentation link on YouTube (contains "YouTube")',
    message: 'Please check out our college project presentation on YouTube: youtube.com/watch?v=academic_demo_402',
    expectedVerdict: 'SAFE',
    expectedMaxScore: 0,
    mustNotTriggerFlags: ['rule_unrealistic_rewards'],
  },
  {
    id: 'REG-CTRL-03',
    category: 'Legitimate Control',
    description: 'Casual personal video like request between classmates',
    message: 'Hey friends, can you please like my sister dance competition video on YouTube? Thank you for the support!',
    expectedVerdict: 'SAFE',
    expectedMaxScore: 0,
    mustNotTriggerFlags: ['rule_unrealistic_rewards'],
  },
  {
    id: 'REG-CTRL-04',
    category: 'Legitimate Control',
    description: 'Official student batch study group Telegram link (contains "Telegram", isolated single signal score <= 15)',
    message: 'Class representative announcement: Join our official physics batch discussion group on Telegram: t.me/physics_batch_2026',
    expectedVerdict: 'SAFE',
    expectedMaxScore: 15,
    mustNotTriggerFlags: ['rule_unrealistic_rewards', 'rule_credentials'],
  },
  {
    id: 'REG-CTRL-05',
    category: 'Legitimate Control',
    description: 'Authentic 6-digit OTP delivery message with defensive warning',
    message: 'Your 6-digit OTP for University Portal login is 582104. Valid for 5 minutes. Do not share your OTP with anyone.',
    expectedVerdict: 'SAFE',
    expectedMaxScore: 0,
    mustNotTriggerFlags: ['rule_credentials'],
  },
  {
    id: 'REG-CTRL-06',
    category: 'Legitimate Control',
    description: 'Defensive bank security alert mentioning "6-digit OTP" and "4-digit PIN"',
    message: 'Bank Security Advisory: Never share your 6-digit OTP or 4-digit PIN with anyone over phone or SMS. Bank officials will never ask for them.',
    expectedVerdict: 'SAFE',
    expectedMaxScore: 0,
    mustNotTriggerFlags: ['rule_credentials'],
  },
  {
    id: 'REG-CTRL-07',
    category: 'Legitimate Control',
    description: 'College library book return notice with overdue charge mention',
    message: 'Campus Library Notice: The book Introduction to Algorithms is due for return by Monday 5 PM to avoid standard Rs 10 overdue charges.',
    expectedVerdict: 'SAFE',
    expectedMaxScore: 0,
    mustNotTriggerFlags: ['rule_job_fee', 'rule_credentials'],
  },
];

export function runRegressionTests() {
  console.log('================================================================================');
  console.log('SCAMLENS PHASE 4 CORRECTIONS REGRESSION TEST SUITE');
  console.log('Testing False Negative Reproductions, Task Scam Variations, Credential Modifiers, and Controls');
  console.log('================================================================================\n');

  let passed = 0;
  let failed = 0;

  for (const c of REGRESSION_CASES) {
    const res = analyzeMessage(c.message);
    const flags = res.warningSigns.map(w => w.id);

    let casePassed = true;
    const failureReasons: string[] = [];

    // Verdict check
    if (res.verdict !== c.expectedVerdict) {
      casePassed = false;
      failureReasons.push(`Expected verdict ${c.expectedVerdict} but got ${res.verdict}`);
    }

    // Min score check
    if (c.expectedMinScore !== undefined && res.score < c.expectedMinScore) {
      casePassed = false;
      failureReasons.push(`Expected min score ${c.expectedMinScore} but got ${res.score}`);
    }

    // Max score check
    if (c.expectedMaxScore !== undefined && res.score > c.expectedMaxScore) {
      casePassed = false;
      failureReasons.push(`Expected max score ${c.expectedMaxScore} but got ${res.score}`);
    }

    // Must trigger flags
    if (c.mustTriggerFlags) {
      for (const f of c.mustTriggerFlags) {
        if (!flags.includes(f)) {
          casePassed = false;
          failureReasons.push(`Missing expected flag: ${f}`);
        }
      }
    }

    // Must not trigger flags
    if (c.mustNotTriggerFlags) {
      for (const f of c.mustNotTriggerFlags) {
        if (flags.includes(f)) {
          casePassed = false;
          failureReasons.push(`Unexpected flag triggered: ${f}`);
        }
      }
    }

    if (casePassed) {
      passed++;
      console.log(`[PASS] [${c.id}] ${c.category}`);
      console.log(`       Verdict: ${res.verdict} (Score: ${res.score}) | Flags: ${flags.join(', ') || 'None'}`);
    } else {
      failed++;
      console.log(`[FAIL] [${c.id}] ${c.category}`);
      console.log(`       Message: "${c.message}"`);
      console.log(`       Verdict: ${res.verdict} (Score: ${res.score}) | Flags: ${flags.join(', ') || 'None'}`);
      console.log(`       Failures: ${failureReasons.join('; ')}`);
    }
    console.log('--------------------------------------------------------------------------------');
  }

  console.log(`\nREGRESSION SUMMARY: ${passed} / ${REGRESSION_CASES.length} PASSED (${failed} failed)`);
  if (failed === 0) {
    console.log('All false negative reproductions, variations, and controls PASSED!\n');
  }
}

runRegressionTests();
