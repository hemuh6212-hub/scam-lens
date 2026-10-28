/**
 * ScamLens Phase 4 Independent Evaluation Audit
 * Dedicated, un-tuned evaluation suite to test the Message Analyzer following Phase 3 updates.
 *
 * Covers 6 mandatory categories:
 * 1. Previously unseen Hinglish scam messages
 * 2. Obfuscated credentials (OTP, UPI PIN, KYC, Password)
 * 3. Legitimate messages containing sensitive keywords (urgent, KYC, bank, payment, OTP)
 * 4. Defensive scam awareness advisories
 * 5. Suspicious messages with and without URLs
 * 6. Borderline / uncertain cases
 *
 * Ground Truth Definitions:
 * - POS: Scam, fraud, or high-risk threat -> Expected Verdict: RISKY or SCAM (score >= 25)
 * - NEG: Legitimate, routine, or benign message -> Expected Verdict: SAFE (score < 25)
 * - UNCERTAIN: Borderline cases where human determination is ambiguous
 */

import { analyzeMessage } from './src/utils/messageAnalyzer';

export interface AuditCase {
  id: string;
  category: string;
  message: string;
  groundTruth: 'POS' | 'NEG' | 'UNCERTAIN';
  expectedVerdict: 'SAFE' | 'RISKY' | 'SCAM' | 'UNCERTAIN';
  expectedScoreRange?: [number, number];
  rationale: string;
}

export const PHASE4_EVALUATION_CASES: AuditCase[] = [
  // =========================================================================
  // CATEGORY 1: PREVIOUSLY UNSEEN HINGLISH SCAM MESSAGES (5 CASES)
  // =========================================================================
  {
    id: 'HIN-NEW-01',
    category: '1. Unseen Hinglish Scams',
    message: 'Namaste, aapka SBI credit card reward points expire hone wale hain. Points redeem karne ke liye turant link par click karein: http://sbi-points-gift.xyz/claim',
    groundTruth: 'POS',
    expectedVerdict: 'SCAM',
    rationale: 'Reward lure with fake banking urgency and disposable phishing domain (.xyz) in Hinglish.',
  },
  {
    id: 'HIN-NEW-02',
    category: '1. Unseen Hinglish Scams',
    message: 'Aapke electricity bill ka bhugtan baki hai, aaj raat 9 baje bijli connection kaat diya jayega. Fauran bijli officer ko call karein.',
    groundTruth: 'POS',
    expectedVerdict: 'RISKY',
    rationale: 'Hinglish utility disconnection extortion threatening cutoff with urgency.',
  },
  {
    id: 'HIN-NEW-03',
    category: '1. Unseen Hinglish Scams',
    message: 'Dear customer, aapka bank khata freeze kar diya gaya hai. Khata chalu rakhne ke liye kripya apna Aadhar update karein.',
    groundTruth: 'POS',
    expectedVerdict: 'RISKY',
    rationale: 'Hinglish fake bank account freezing threat demanding Aadhaar update.',
  },
  {
    id: 'HIN-NEW-04',
    category: '1. Unseen Hinglish Scams',
    message: 'Online work from home task: Rozana YouTube video like karke 2000 rupaye kamayein. Sampark karein Telegram par t.me/taskincome99',
    groundTruth: 'POS',
    expectedVerdict: 'SCAM',
    rationale: 'Work-from-home task scam promising daily income for video likes redirected to Telegram.',
  },
  {
    id: 'HIN-NEW-05',
    category: '1. Unseen Hinglish Scams',
    message: 'Aapka parcel delivery address galat hone se hold par hai. Address update karein aur redelivery fee pay karein: bit.ly/indiapost-pkg',
    groundTruth: 'POS',
    expectedVerdict: 'SCAM',
    rationale: 'Courier delivery failure phishing lure demanding redelivery fee via bit.ly link.',
  },

  // =========================================================================
  // CATEGORY 2: OBFUSCATED CREDENTIALS (OTP, UPI PIN, KYC, PASSWORD) (6 CASES)
  // =========================================================================
  {
    id: 'OBF-NEW-01',
    category: '2. Obfuscated Credentials',
    message: 'Verification alert: Please forward the 6-digit O*T*P received on your mobile to complete authorization.',
    groundTruth: 'POS',
    expectedVerdict: 'RISKY',
    rationale: 'Asterisk-obfuscated O*T*P with forward/share credential demand.',
  },
  {
    id: 'OBF-NEW-02',
    category: '2. Obfuscated Credentials',
    message: 'Attention user: Enter your U_P_I P_I_N to receive the pending cash prize into your bank account immediately.',
    groundTruth: 'POS',
    expectedVerdict: 'SCAM',
    rationale: 'Underscore-obfuscated U_P_I P_I_N combined with UPI receive money trap and urgent reward lure.',
  },
  {
    id: 'OBF-NEW-03',
    category: '2. Obfuscated Credentials',
    message: 'Security notice: Your bank K-Y-C is pending. Update your P.A.N. card urgently or account will be permanently blocked.',
    groundTruth: 'POS',
    expectedVerdict: 'SCAM',
    rationale: 'Hyphen-obfuscated K-Y-C with urgent threat of permanent account deactivation.',
  },
  {
    id: 'OBF-NEW-04',
    category: '2. Obfuscated Credentials',
    message: 'Dear user, share your P.A.S.S.W.O.R.D and M-P-I-N with our support executive to unlock your online banking.',
    groundTruth: 'POS',
    expectedVerdict: 'RISKY',
    rationale: 'Punctuation-separated password and MPIN solicitation to unlock account.',
  },
  {
    id: 'OBF-NEW-05',
    category: '2. Obfuscated Credentials',
    message: 'Urgent: Send your C.V.V and O/T/P immediately or card will be permanently suspended within 2 hours.',
    groundTruth: 'POS',
    expectedVerdict: 'SCAM',
    rationale: 'Slash-obfuscated O/T/P and dot C.V.V solicitation with artificial urgency deadline.',
  },
  {
    id: 'OBF-NEW-06',
    category: '2. Obfuscated Credentials',
    message: 'Your refund of Rs 4,500 has been sanctioned. Kindly enter your U P I P I N to authorize the pending refund.',
    groundTruth: 'POS',
    expectedVerdict: 'SCAM',
    rationale: 'Space-separated U P I P I N in fraudulent refund claim.',
  },

  // =========================================================================
  // CATEGORY 3: LEGITIMATE MESSAGES WITH SENSITIVE KEYWORDS (7 CASES)
  // =========================================================================
  {
    id: 'LEG-NEW-01',
    category: '3. Legitimate with Sensitive Words',
    message: 'Your OTP for logging into the University Student Portal is 482910. Valid for 10 minutes. Do not share your OTP with anyone.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Standard authentication OTP delivery with clear defensive warning not to share.',
  },
  {
    id: 'LEG-NEW-02',
    category: '3. Legitimate with Sensitive Words',
    message: 'Payment of Rs 1,850 to Campus Cafeteria completed successfully via UPI on 25-Oct. Transaction Ref: 9382103948.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Routine debit confirmation alert with payment and UPI keywords.',
  },
  {
    id: 'LEG-NEW-03',
    category: '3. Legitimate with Sensitive Words',
    message: 'Dear Student, your annual bank statement for account ending 4012 is ready for download in your netbanking portal.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Standard banking communication with no coercive links or credential requests.',
  },
  {
    id: 'LEG-NEW-04',
    category: '3. Legitimate with Sensitive Words',
    message: 'Academic Notice: All students must submit semester exam fees at the accounts department counter before Friday 4 PM.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Legitimate college fee notice referring to physical campus payment counter.',
  },
  {
    id: 'LEG-NEW-05',
    category: '3. Legitimate with Sensitive Words',
    message: 'Your scheduled KYC renewal at HDFC Bank MG Road Branch has been confirmed for Friday, 11:00 AM. Please bring physical ID proof to the branch.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Physical in-branch appointment confirmation for KYC renewal with no phishing links or panic threats.',
  },
  {
    id: 'LEG-NEW-06',
    category: '3. Legitimate with Sensitive Words',
    message: 'Your monthly broadband bill of Rs 799 has been generated. Due date is 05-Nov. View details on your customer portal.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Legitimate utility bill generation notification with future due date and no cutoff extortion.',
  },
  {
    id: 'LEG-NEW-07',
    category: '3. Legitimate with Sensitive Words',
    message: 'Classroom update: Tomorrow morning lecture on Database Management Systems will start at 9:00 AM in Hall 4.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Routine benign student scheduling notice.',
  },

  // =========================================================================
  // CATEGORY 4: DEFENSIVE SCAM AWARENESS ADVISORIES (4 CASES)
  // =========================================================================
  {
    id: 'ADV-NEW-01',
    category: '4. Scam Awareness Advisories',
    message: 'RBI Kehta Hai: Kabhi bhi kisi ko apna OTP, UPI PIN, ya bank password na batayein. Bank kabhi aisi jankari nahi mangta.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Official Reserve Bank of India consumer awareness message educating public against sharing credentials in Hindi/Hinglish.',
  },
  {
    id: 'ADV-NEW-02',
    category: '4. Scam Awareness Advisories',
    message: 'Cyber Crime Police Advisory: Beware of fake calls threatening digital arrest or parcel confiscation. Police and CBI never make video calls demanding money.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Official law enforcement advisory alerting citizens about digital arrest extortion scams.',
  },
  {
    id: 'ADV-NEW-03',
    category: '4. Scam Awareness Advisories',
    message: 'Bank Advisory: Never share your OTP, PIN or passwords with anyone. Our bank representatives will never ask you for secret credentials.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Defensive banking advisory educating customers against fraud.',
  },
  {
    id: 'ADV-NEW-04',
    category: '4. Scam Awareness Advisories',
    message: 'Student Council Warning: Beware of fraudulent recruiters asking for registration fees or laptop deposits on Telegram. Report such messages immediately.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Educational warning message by student council alerting peers to job scams.',
  },

  // =========================================================================
  // CATEGORY 5: SUSPICIOUS MESSAGES WITH AND WITHOUT URLS (6 CASES)
  // =========================================================================
  {
    id: 'SUSP-NEW-01',
    category: '5. Suspicious Messages (With URLs)',
    message: 'Your parcel failed delivery due to missing apartment number. Update your details and pay Rs 25 redelivery charge at http://indiapost-track-shipment.xyz/update immediately.',
    groundTruth: 'POS',
    expectedVerdict: 'SCAM',
    rationale: 'Postal package failure lure with redelivery fee and disposable .xyz phishing URL.',
  },
  {
    id: 'SUSP-NEW-02',
    category: '5. Suspicious Messages (With URLs)',
    message: 'Selected for Part-Time Amazon Reviewer job! Earn Rs 3,000 daily from home. Contact HR recruiter via Telegram at t.me/amazonhrwork',
    groundTruth: 'POS',
    expectedVerdict: 'SCAM',
    rationale: 'Task scam with daily guaranteed earnings and off-platform Telegram recruitment link.',
  },
  {
    id: 'SUSP-NEW-03',
    category: '5. Suspicious Messages (With URLs)',
    message: 'Dear customer, your bank account access has been restricted. Download our verification app at http://192.168.1.105/bank-update.apk to restore access.',
    groundTruth: 'POS',
    expectedVerdict: 'SCAM',
    rationale: 'Account restriction scare paired with raw IP address hosting an APK file download.',
  },
  {
    id: 'SUSP-NEW-04',
    category: '5. Suspicious Messages (Without URLs)',
    message: 'Final Notice: CBI Cyber Cell has issued an arrest warrant against you for illegal narcotics parcel. Stay on video call or face immediate police detention.',
    groundTruth: 'POS',
    expectedVerdict: 'RISKY',
    rationale: 'High-pressure digital arrest coercion impersonating CBI with arrest threats without any URL.',
  },
  {
    id: 'SUSP-NEW-05',
    category: '5. Suspicious Messages (Without URLs)',
    message: 'Shortlisted for Google Developer Summer Apprenticeship! Pay a refundable onboarding security fee of Rs 2,500 via UPI to confirm your kit.',
    groundTruth: 'POS',
    expectedVerdict: 'RISKY',
    rationale: 'Recruitment scam demanding upfront refundable fee/kit charge without any URL.',
  },
  {
    id: 'SUSP-NEW-06',
    category: '5. Suspicious Messages (Without URLs)',
    message: 'Pre-approved student education loan of Rs 2,00,000 sanctioned. Transfer advance processing fee of Rs 2,000 to disburse loan amount today.',
    groundTruth: 'POS',
    expectedVerdict: 'RISKY',
    rationale: 'Advance-fee predatory loan scheme demanding upfront deposit to release funds without URL.',
  },

  // =========================================================================
  // CATEGORY 6: BORDERLINE / UNCERTAIN CASES (4 CASES)
  // =========================================================================
  {
    id: 'BORD-NEW-01',
    category: '6. Borderline / Uncertain',
    message: 'Urgent: Please call your branch manager regarding irregular activity on your card.',
    groundTruth: 'UNCERTAIN',
    expectedVerdict: 'UNCERTAIN',
    rationale: 'Vague urgency and banking context, but no link, no credential request, and advises contacting branch manager.',
  },
  {
    id: 'BORD-NEW-02',
    category: '6. Borderline / Uncertain',
    message: 'Hey, did you send that 500 rupees payment earlier? Let me know once done.',
    groundTruth: 'NEG',
    expectedVerdict: 'SAFE',
    rationale: 'Informal personal payment query between acquaintances; contains "payment" and monetary amount but lacks coercion.',
  },
  {
    id: 'BORD-NEW-03',
    category: '6. Borderline / Uncertain',
    message: 'Exclusive campus offer: Click here to claim 50% discount on tech course: bit.ly/student-deal',
    groundTruth: 'UNCERTAIN',
    expectedVerdict: 'UNCERTAIN',
    rationale: 'Aggressive educational marketing with shortened bit.ly URL; borderline between commercial promotional spam and suspicious link.',
  },
  {
    id: 'BORD-NEW-04',
    category: '6. Borderline / Uncertain',
    message: 'Your verification code is 9182. Use this to complete your registration.',
    groundTruth: 'UNCERTAIN',
    expectedVerdict: 'UNCERTAIN',
    rationale: 'Generic verification code message lacking sender identity or standard "do not share" warning, making authentic origin ambiguous.',
  },
];

// Runner logic
export function runEvaluationAudit() {
  console.log('================================================================================');
  console.log('SCAMLENS PHASE 4: MESSAGE ANALYZER EVALUATION AUDIT');
  console.log('Testing against completely new, un-tuned evaluation cases');
  console.log('================================================================================\n');

  let totalCases = PHASE4_EVALUATION_CASES.length;
  let evaluatedCases = 0;
  let excludedUncertain = 0;

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  const categoryStats: Record<string, { total: number; correct: number; discrepancies: number }> = {};
  const disagreements: Array<{
    id: string;
    category: string;
    message: string;
    groundTruth: string;
    expected: string;
    actualVerdict: string;
    actualScore: number;
    flags: string[];
    rationale: string;
  }> = [];

  for (const c of PHASE4_EVALUATION_CASES) {
    if (!categoryStats[c.category]) {
      categoryStats[c.category] = { total: 0, correct: 0, discrepancies: 0 };
    }
    categoryStats[c.category].total++;

    const result = analyzeMessage(c.message);
    const actualVerdict = result.verdict;
    const actualScore = result.score;
    const flagIds = result.warningSigns.map(w => w.id);

    // Binary mapping:
    // POS expected to trigger warning (RISKY or SCAM, score >= 25)
    // NEG expected to be clean (SAFE, score < 25)
    if (c.groundTruth === 'UNCERTAIN') {
      excludedUncertain++;
      console.log(`[${c.id}] (UNCERTAIN) Verdict: ${actualVerdict} (Score: ${actualScore}) | Flags: ${flagIds.join(', ') || 'None'}`);
      console.log(`  Message: "${c.message}"`);
      console.log(`  Notes: ${c.rationale}\n`);
      continue;
    }

    evaluatedCases++;
    const isThreatDetected = actualVerdict === 'RISKY' || actualVerdict === 'SCAM';

    let isBinaryCorrect = false;
    if (c.groundTruth === 'POS') {
      if (isThreatDetected) {
        tp++;
        isBinaryCorrect = true;
      } else {
        fn++;
        isBinaryCorrect = false;
      }
    } else if (c.groundTruth === 'NEG') {
      if (!isThreatDetected) {
        tn++;
        isBinaryCorrect = true;
      } else {
        fp++;
        isBinaryCorrect = false;
      }
    }

    if (isBinaryCorrect) {
      categoryStats[c.category].correct++;
      console.log(`[PASS] [${c.id}] (${c.groundTruth}) -> ${actualVerdict} (Score: ${actualScore})`);
    } else {
      categoryStats[c.category].discrepancies++;
      console.log(`[DISCREPANCY] [${c.id}] Expected ${c.groundTruth} (${c.expectedVerdict}) but got ${actualVerdict} (Score: ${actualScore})`);
      disagreements.push({
        id: c.id,
        category: c.category,
        message: c.message,
        groundTruth: c.groundTruth,
        expected: c.expectedVerdict,
        actualVerdict,
        actualScore,
        flags: flagIds,
        rationale: c.rationale,
      });
    }
  }

  // Calculate Metrics
  const accuracy = (tp + tn) / evaluatedCases;
  const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
  const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
  const fpr = (fp + tn) > 0 ? fp / (fp + tn) : 0;
  const fnr = (fn + tp) > 0 ? fn / (fn + tp) : 0;

  console.log('\n================================================================================');
  console.log('EVALUATION METRICS SUMMARY');
  console.log('================================================================================');
  console.log(`Total Test Cases in Suite:        ${totalCases}`);
  console.log(`Statistically Evaluated Cases:    ${evaluatedCases}`);
  console.log(`Excluded Borderline/Uncertain:   ${excludedUncertain}`);
  console.log(`True Positives (TP):              ${tp}`);
  console.log(`False Positives (FP):             ${fp}`);
  console.log(`True Negatives (TN):              ${tn}`);
  console.log(`False Negatives (FN):             ${fn}`);
  console.log('--------------------------------------------------------------------------------');
  console.log(`Accuracy:                         ${(accuracy * 100).toFixed(2)}% (${tp + tn}/${evaluatedCases})`);
  console.log(`Precision (Scam/Threat):          ${(precision * 100).toFixed(2)}% (${tp}/${tp + fp})`);
  console.log(`Recall (Scam/Threat):             ${(recall * 100).toFixed(2)}% (${tp}/${tp + fn})`);
  console.log(`False Positive Rate (FPR):        ${(fpr * 100).toFixed(2)}% (${fp}/${fp + tn})`);
  console.log(`False Negative Rate (FNR):        ${(fnr * 100).toFixed(2)}% (${fn}/${fn + tp})`);

  console.log('\n================================================================================');
  console.log('CATEGORY BREAKDOWN');
  console.log('================================================================================');
  for (const [cat, stat] of Object.entries(categoryStats)) {
    console.log(`${cat.padEnd(38)}: ${stat.correct}/${stat.total - (cat.includes('Uncertain') ? excludedUncertain : 0)} correct (${stat.discrepancies} discrepancies)`);
  }

  if (disagreements.length > 0) {
    console.log('\n================================================================================');
    console.log('DISCREPANCIES & DISAGREEMENTS');
    console.log('================================================================================');
    for (const d of disagreements) {
      console.log(`Case ID:         ${d.id}`);
      console.log(`Category:        ${d.category}`);
      console.log(`Message:         "${d.message}"`);
      console.log(`Ground Truth:    ${d.groundTruth} (Expected: ${d.expected})`);
      console.log(`Detector Result: ${d.actualVerdict} (Score: ${d.actualScore})`);
      console.log(`Flags Triggered: ${d.flags.join(', ') || 'None'}`);
      console.log(`Rationale:       ${d.rationale}`);
      console.log('--------------------------------------------------------------------------------');
    }
  } else {
    console.log('\nAll non-uncertain evaluated cases matched expected binary threat classifications!');
  }
}

runEvaluationAudit();
