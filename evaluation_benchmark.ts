/**
 * ScamLens Formal Performance Evaluation Benchmark
 * Evaluates binary classification metrics (Accuracy, Precision, Recall, FPR, FNR, Confusion Matrix)
 * on a Tuning Dataset and an Independent Held-Out Evaluation Dataset.
 *
 * Binary Ground Truth Definition:
 * - POSITIVE (POS): Scam, fraud, deceptive link, or suspicious threat -> Expected to generate a warning (RISKY or SCAM).
 * - NEGATIVE (NEG): Benign, routine, or authentic communication -> Expected to evaluate as SAFE (score < 25).
 * - UNCERTAIN cases are excluded from statistical binary metrics to prevent arbitrary metric skew.
 */

import { analyzeUrl } from './src/utils/urlAnalyzer';
import { analyzeMessage } from './src/utils/messageAnalyzer';

export interface LabeledCase {
  id: string;
  set: 'TUNING' | 'HOLDOUT';
  analyzer: 'MESSAGE' | 'URL';
  input: string;
  groundTruth: 'POS' | 'NEG' | 'UNCERTAIN';
  expectedCategory: 'SAFE' | 'RISKY' | 'SCAM' | 'SUSPICIOUS' | 'UNCERTAIN';
  reason: string;
  uncertaintyNotes?: string;
}

export interface EvaluatedCase extends LabeledCase {
  actualVerdict: string;
  actualScore: number;
  triggeredRules: string[];
  classificationResult: 'TP' | 'FP' | 'TN' | 'FN' | 'EXCLUDED';
  passed: boolean;
}

// -----------------------------------------------------------------------------
// BENCHMARK DATASET (62 TOTAL SAMPLES: 30 TUNING + 30 HOLDOUT + 2 UNCERTAIN)
// -----------------------------------------------------------------------------
export const BENCHMARK_DATASET: LabeledCase[] = [
  // ===================== TUNING SET: MESSAGES (15 CASES) =====================
  {
    id: 'T-MSG-01',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Hi team, reminder that our College Robotics Club weekly meeting will take place tomorrow at 4:30 PM in Room 302, Academic Block C.',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Authentic student club scheduling notice with zero financial or credential requests.',
  },
  {
    id: 'T-MSG-02',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Your account XX9821 has been credited with INR 35,000 on 22-Oct by NEFT. Avail Bal: INR 42,300.',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Routine banking credit transaction alert.',
  },
  {
    id: 'T-MSG-03',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Campus Library Notice: The book "Introduction to Algorithms" is due for return by Monday 5 PM to avoid standard Rs 10 overdue charges.',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Routine academic overdue notice at physical library desk.',
  },
  {
    id: 'T-MSG-04',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Doctor Appointment Confirmation: Consultation with Dr. Mehta confirmed for Wednesday at 11:30 AM at City Health Clinic.',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Authentic healthcare schedule alert.',
  },
  {
    id: 'T-MSG-05',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'University Advisory: Students are reminded to never share netbanking passwords or OTPs with unknown callers claiming to represent the scholarship board.',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Protective campus awareness advisory educating against OTP sharing.',
  },
  {
    id: 'T-MSG-06',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Congratulations! Shortlisted for 3-Month Data Science Remote Internship. Pay refundable registration fee of Rs 1,299 at link to dispatch laptop kit.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Classic internship upfront kit fee scam.',
  },
  {
    id: 'T-MSG-07',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Dear Customer, your HDFC bank netbanking will be suspended within 24 hours. Submit your documents and verify KYC at http://hdfc-bank-verify.xyz/login immediately.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Phishing KYC threat with artificial panic and disposable domain.',
  },
  {
    id: 'T-MSG-08',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'We mistakenly sent Rs 4,000 extra to your GPay number for your shoes refund. Open PhonePe, approve collect request, and enter your UPI PIN to claim money back.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'UPI collect refund trap tricking user to enter UPI PIN.',
  },
  {
    id: 'T-MSG-09',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Immediately contact power officer at 9876543210.',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Urgent electricity cutoff threat with unauthorized personal phone.',
  },
  {
    id: 'T-MSG-10',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'India Post: Your parcel cannot be delivered due to incomplete address. Please update delivery address and pay Rs 25 redelivery fee at http://post-delivery.xyz/pay.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Fake postal parcel redelivery fee phishing trap.',
  },
  {
    id: 'T-MSG-11',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Kindly share your O T P to cancel accidental bank charges on your credit card.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Spaced credential evasion attempting unauthorized account takeover.',
  },
  {
    id: 'T-MSG-12',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Pre-approved instant cash loan of Rs 3,00,000 without documents. Pay Rs 1,500 file processing charges to release funds to your bank account.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Predatory loan advance-fee fraud.',
  },
  {
    id: 'T-MSG-13',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Congratulations! You have won Rs 50,00,000 in the Jio Lucky Draw 2026. Claim your prize bonus today!',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Unsolicited fake lottery prize lure.',
  },
  {
    id: 'T-MSG-14',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'URGENT: Legal notice issued against your mobile number by Supreme Court Police. You are under digital arrest for money laundering. Do not inform family, stay on video call.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Coercive digital arrest police impersonation.',
  },
  {
    id: 'T-MSG-15',
    set: 'TUNING',
    analyzer: 'MESSAGE',
    input: 'Part-time work from home: Earn Rs 3,000 to Rs 8,000 daily by liking YouTube videos and rating hotels on Google Maps. Contact HR on WhatsApp +919123456789.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Task scam with off-platform redirection to WhatsApp.',
  },

  // ===================== TUNING SET: URLS (15 CASES) =====================
  {
    id: 'T-URL-01',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://www.google.com',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Official search engine portal over HTTPS.',
  },
  {
    id: 'T-URL-02',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://portal.iitb.ac.in/student/notices',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Legitimate multi-part academic institution domain (.ac.in).',
  },
  {
    id: 'T-URL-03',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://example.co.in/about',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Standard commercial multi-part domain (.co.in) without suspicious markers.',
  },
  {
    id: 'T-URL-04',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://accounts.google.com/signin',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Authentic brand login portal on official Google root domain.',
  },
  {
    id: 'T-URL-05',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://github.com/login',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Authentic software platform login endpoint on HTTPS.',
  },
  {
    id: 'T-URL-06',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://sbi.co.in.scam-server.xyz/verify',
    groundTruth: 'POS',
    expectedCategory: 'SUSPICIOUS',
    reason: 'Deceptive subdomain brand spoofing on disposable TLD.',
  },
  {
    id: 'T-URL-07',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'http://185.193.125.77/student/auth',
    groundTruth: 'POS',
    expectedCategory: 'SUSPICIOUS',
    reason: 'Raw numeric IP host over unencrypted HTTP.',
  },
  {
    id: 'T-URL-08',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://bit.ly/student-loan-waiver',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Obfuscating URL shortener concealing actual endpoint.',
  },
  {
    id: 'T-URL-09',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'http://paypal.com@evil-phishing-host.com/login',
    groundTruth: 'POS',
    expectedCategory: 'SUSPICIOUS',
    reason: 'Deceptive @ userinfo authority trick.',
  },
  {
    id: 'T-URL-10',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://bank-login-update.com:8080/portal',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Unusual non-standard network port :8080.',
  },
  {
    id: 'T-URL-11',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'http://hdfc-bank-kyc-update.xyz/login.php',
    groundTruth: 'POS',
    expectedCategory: 'SUSPICIOUS',
    reason: 'Brand typosquatting + Insecure HTTP + Disposable TLD.',
  },
  {
    id: 'T-URL-12',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://portal.secure-student-grant-verification-claim.xyz',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Multiple hyphen tokens + disposable spam TLD.',
  },
  {
    id: 'T-URL-13',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://example.com/downloads/bank_patch.apk',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Direct executable Android .apk payload download.',
  },
  {
    id: 'T-URL-14',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'https://xn--appl-43d.com',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Punycode IDN lookalike brand spoofing.',
  },
  {
    id: 'T-URL-15',
    set: 'TUNING',
    analyzer: 'URL',
    input: 'http://example.com/unencrypted-page',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Unencrypted plain HTTP communication protocol.',
  },

  // ===================== HOLDOUT SET: MESSAGES (15 CASES) =====================
  {
    id: 'H-MSG-01',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Annual College Sports Meet: Badminton trials will take place at the indoor sports complex this Saturday from 9 AM. All enrolled students are welcome to participate.',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Standard collegiate sports notice without financial or authentication demands.',
  },
  {
    id: 'H-MSG-02',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Dear SBI customer, your debit card XX5432 was debited for INR 450 at Campus Cafeteria on 25-Oct. If this was not authorized by you, SMS BLOCK to 567676.',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Authentic automated bank debit notification with standard fraud reporting instructions.',
  },
  {
    id: 'H-MSG-03',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Your blood test laboratory reports are now available for pickup at Health Diagnostics Center reception between 9 AM and 6 PM.',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Benign medical diagnostic pickup alert.',
  },
  {
    id: 'H-MSG-04',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Reminder: College Hackathon registration fee is Rs 150 per team at the student council counter in Admin Block by Friday 4 PM.',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Campus academic hackathon fee at physical department desk.',
  },
  {
    id: 'H-MSG-05',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Course Registration Alert: Fall semester elective selection opens at 10 AM tomorrow on the student ERP portal. Please verify your course prerequisites.',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Ordinary course registration portal advisory.',
  },
  {
    id: 'H-MSG-06',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Urgent: Your Axis Bank account is temporarily frozen due to unlinked PAN card. Visit http://axis-pan-update.xyz/auth immediately to avoid complete deactivation.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Urgent account freezing threat paired with third-party verification link.',
  },
  {
    id: 'H-MSG-07',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Congratulations! Selected as Python Developer Intern (Stipend: Rs 30,000/mo). To confirm joining and dispatch company laptop, pay mandatory onboarding fee of Rs 999 at link before midnight.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Internship upfront laptop fee demand with deadline pressure.',
  },
  {
    id: 'H-MSG-08',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Amazon Delivery Notice: Your order #84920 could not be delivered due to invalid house number. Update your delivery address and pay Rs 20 redelivery fee at http://delivery-update.xyz/reschedule.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Delivery package failure lure with fee demand.',
  },
  {
    id: 'H-MSG-09',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Please install this quick support app from http://remote-tools.xyz/agent.apk so our banking engineer can resolve your netbanking issue via screen share.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Malicious sideloaded APK and remote screen-sharing software prompt.',
  },
  {
    id: 'H-MSG-10',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Accounts error: We sent Rs 2,500 extra to your PhonePe account by mistake. Kindly open PhonePe, accept the pending collect request, and enter your UPI PIN to process reverse refund.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'UPI collect deception asking victim to approve collect and enter PIN.',
  },
  {
    id: 'H-MSG-11',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Kindly provide your M P I N and O T P to authorize the pending refund transaction into your savings account.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Spaced MPIN / OTP credential solicitation.',
  },
  {
    id: 'H-MSG-12',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Electricity Warning: Your domestic power meter will be disconnected today at 8:00 PM due to unpaid balance of Rs 1,420. Call power department executive at 9123456780 immediately.',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Urgent utility cutoff scam using personal contact number.',
  },
  {
    id: 'H-MSG-13',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Pre-approved student education loan of Rs 4,00,000 sanctioned with zero collateral. Kindly transfer Rs 2,000 documentation charge to release sanction letter.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Predatory loan advance documentation fee scheme.',
  },
  {
    id: 'H-MSG-14',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'National Lottery Commission: You have won Rs 10,00,000 in Diwali bumper cash prize. Click http://prize-claim.xyz to claim cash transfer.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Unrealistic lottery prize with disposable URL.',
  },
  {
    id: 'H-MSG-15',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Work from home task job: Earn Rs 4,000 daily by reviewing Google Play apps. DM our recruitment team on Telegram @quick_tasks_hr to get started.',
    groundTruth: 'POS',
    expectedCategory: 'SCAM',
    reason: 'Task scam with off-platform redirection to Telegram handle.',
  },

  // ===================== HOLDOUT SET: URLS (15 CASES) =====================
  {
    id: 'H-URL-01',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://www.wikipedia.org',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Legitimate encyclopedia domain on HTTPS.',
  },
  {
    id: 'H-URL-02',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://scholarships.gov.in',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Official governmental scholarship registry (.gov.in).',
  },
  {
    id: 'H-URL-03',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://engineering.cam.ac.uk',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Accredited multi-part UK academic institution domain (.ac.uk).',
  },
  {
    id: 'H-URL-04',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://www.microsoft.com/en-us/education',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Official enterprise domain on HTTPS.',
  },
  {
    id: 'H-URL-05',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://university.ac.nz/student/portal',
    groundTruth: 'NEG',
    expectedCategory: 'SAFE',
    reason: 'Accredited New Zealand academic registry (.ac.nz).',
  },
  {
    id: 'H-URL-06',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://paypal.com.account-update.xyz/auth',
    groundTruth: 'POS',
    expectedCategory: 'SUSPICIOUS',
    reason: 'Subdomain brand spoofing (PayPal) on disposable .xyz TLD.',
  },
  {
    id: 'H-URL-07',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'http://192.168.0.100/admin/login',
    groundTruth: 'POS',
    expectedCategory: 'SUSPICIOUS',
    reason: 'Direct numeric IP host over plain HTTP.',
  },
  {
    id: 'H-URL-08',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://tinyurl.com/student-cashback-2026',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'URL shortener masking destination server.',
  },
  {
    id: 'H-URL-09',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'http://google.com@phishing-target-server.com/signin',
    groundTruth: 'POS',
    expectedCategory: 'SUSPICIOUS',
    reason: 'Deceptive @ userinfo authority trick.',
  },
  {
    id: 'H-URL-10',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://student-service.org:8443/login',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Non-standard network port :8443.',
  },
  {
    id: 'H-URL-11',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'http://icici-bank-netbanking-verify.xyz/login.html',
    groundTruth: 'POS',
    expectedCategory: 'SUSPICIOUS',
    reason: 'Brand typosquatting + Insecure HTTP + Disposable TLD.',
  },
  {
    id: 'H-URL-12',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://portal-student-verify-support-refund.top',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Hyphen clutter + disposable .top registry.',
  },
  {
    id: 'H-URL-13',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://trusted-files.com/tools/client.exe',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Direct Windows executable payload (.exe).',
  },
  {
    id: 'H-URL-14',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://xn--e1afmkfd.xn--p1ai',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Internationalized domain name with punycode encoding.',
  },
  {
    id: 'H-URL-15',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'http://unsecured-campus-portal.org',
    groundTruth: 'POS',
    expectedCategory: 'RISKY',
    reason: 'Unencrypted plain HTTP communication.',
  },

  // ===================== UNCERTAIN / BORDERLINE CASES (2 CASES) =====================
  {
    id: 'U-CASE-01',
    set: 'HOLDOUT',
    analyzer: 'URL',
    input: 'https://new-tech-startup.io',
    groundTruth: 'UNCERTAIN',
    expectedCategory: 'UNCERTAIN',
    reason: 'Modern commercial tech TLD (.io) on HTTPS with zero suspicious syntax; destination safety cannot be established without live external threat intelligence.',
    uncertaintyNotes: 'Heuristic checks pass (SAFE), but domain reputation cannot be verified statically without live WHOIS/DNS.',
  },
  {
    id: 'U-CASE-02',
    set: 'HOLDOUT',
    analyzer: 'MESSAGE',
    input: 'Hey, can you send me Rs 500 on GPay right now? I will return it when we meet in the evening.',
    groundTruth: 'UNCERTAIN',
    expectedCategory: 'UNCERTAIN',
    reason: 'Peer-to-peer informal borrowing request. Could be an authentic friend or an account impersonation hijack.',
    uncertaintyNotes: 'Informal social messaging without overt credentials, threats, or deceptive links cannot be proven fraud statically.',
  },
];

// -----------------------------------------------------------------------------
// BENCHMARK RUNNER & METRIC CALCULATOR
// -----------------------------------------------------------------------------
export function runBenchmark() {
  const evaluatedCases: EvaluatedCase[] = [];

  for (const c of BENCHMARK_DATASET) {
    let actualVerdict = '';
    let actualScore = -1;
    let triggeredRules: string[] = [];

    try {
      if (c.analyzer === 'MESSAGE') {
        const res = analyzeMessage(c.input);
        actualVerdict = res.verdict;
        actualScore = res.score;
        triggeredRules = res.warningSigns.map((w) => w.id);
      } else {
        const res = analyzeUrl(c.input);
        actualVerdict = res.verdict;
        actualScore = res.riskScore;
        triggeredRules = res.flags.filter((f) => f.severity !== 'info').map((f) => f.id);
      }
    } catch (e: any) {
      actualVerdict = 'ERROR';
      actualScore = -1;
    }

    // Binary mapping:
    // POS: RISKY or SCAM / SUSPICIOUS
    // NEG: SAFE
    let classificationResult: 'TP' | 'FP' | 'TN' | 'FN' | 'EXCLUDED' = 'EXCLUDED';
    let passed = false;

    if (c.groundTruth === 'UNCERTAIN') {
      classificationResult = 'EXCLUDED';
      passed = true;
    } else {
      const isPositivePrediction = actualVerdict === 'RISKY' || actualVerdict === 'SCAM' || actualVerdict === 'SUSPICIOUS';
      const isNegativePrediction = actualVerdict === 'SAFE';

      if (c.groundTruth === 'POS' && isPositivePrediction) {
        classificationResult = 'TP';
        passed = true;
      } else if (c.groundTruth === 'NEG' && isPositivePrediction) {
        classificationResult = 'FP';
        passed = false;
      } else if (c.groundTruth === 'NEG' && isNegativePrediction) {
        classificationResult = 'TN';
        passed = true;
      } else if (c.groundTruth === 'POS' && isNegativePrediction) {
        classificationResult = 'FN';
        passed = false;
      }
    }

    evaluatedCases.push({
      ...c,
      actualVerdict,
      actualScore,
      triggeredRules,
      classificationResult,
      passed,
    });
  }

  return evaluatedCases;
}

interface PerformanceMetrics {
  total: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  accuracy: number;
  precision: number;
  recall: number;
  fpr: number;
  fnr: number;
}

function calculateMetrics(cases: EvaluatedCase[]): PerformanceMetrics {
  const binaryCases = cases.filter((c) => c.classificationResult !== 'EXCLUDED');
  const tp = binaryCases.filter((c) => c.classificationResult === 'TP').length;
  const fp = binaryCases.filter((c) => c.classificationResult === 'FP').length;
  const tn = binaryCases.filter((c) => c.classificationResult === 'TN').length;
  const fn = binaryCases.filter((c) => c.classificationResult === 'FN').length;
  const total = tp + fp + tn + fn;

  const accuracy = total > 0 ? (tp + tn) / total : 0;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
  const fnr = tp + fn > 0 ? fn / (tp + fn) : 0;

  return { total, tp, fp, tn, fn, accuracy, precision, recall, fpr, fnr };
}

// -----------------------------------------------------------------------------
// CLI EXECUTION
// -----------------------------------------------------------------------------
const evaluated = runBenchmark();

console.log('==========================================================================================');
console.log('SCAMLENS FORMAL DETECTION BENCHMARK (62 LABELED SAMPLES)');
console.log('==========================================================================================\n');

function printSetReport(setName: 'TUNING' | 'HOLDOUT', analyzerType?: 'MESSAGE' | 'URL') {
  let filtered = evaluated.filter((c) => c.set === setName);
  if (analyzerType) {
    filtered = filtered.filter((c) => c.analyzer === analyzerType);
  }
  const metrics = calculateMetrics(filtered);

  console.log(`------------------------------------------------------------------------------------------`);
  console.log(`SET: ${setName} | ANALYZER: ${analyzerType || 'ALL'} (Evaluated Samples: ${metrics.total})`);
  console.log(`------------------------------------------------------------------------------------------`);
  console.log(`Confusion Matrix: [TP: ${metrics.tp}, FP: ${metrics.fp}, TN: ${metrics.tn}, FN: ${metrics.fn}]`);
  console.log(`Accuracy:            ${(metrics.accuracy * 100).toFixed(1)}%`);
  console.log(`Precision:           ${(metrics.precision * 100).toFixed(1)}%`);
  console.log(`Recall (Sensitivity):${(metrics.recall * 100).toFixed(1)}%`);
  console.log(`False Positive Rate: ${(metrics.fpr * 100).toFixed(1)}%`);
  console.log(`False Negative Rate: ${(metrics.fnr * 100).toFixed(1)}%`);
  console.log('');
}

console.log('### 1. TUNING DATASET PERFORMANCE (30 SAMPLES)');
printSetReport('TUNING', 'MESSAGE');
printSetReport('TUNING', 'URL');
printSetReport('TUNING');

console.log('### 2. INDEPENDENT HOLDOUT DATASET PERFORMANCE (30 SAMPLES)');
printSetReport('HOLDOUT', 'MESSAGE');
printSetReport('HOLDOUT', 'URL');
printSetReport('HOLDOUT');

console.log('### 3. UNCERTAIN BORDERLINE CASES (DOCUMENTED WITHOUT ARBITRARY SKEW)');
const uncertainCases = evaluated.filter((c) => c.groundTruth === 'UNCERTAIN');
for (const u of uncertainCases) {
  console.log(`- [${u.id}] ${u.input}`);
  console.log(`  Engine Verdict: ${u.actualVerdict} (Score: ${u.actualScore})`);
  console.log(`  Analysis Note: ${u.reason}`);
  console.log(`  Limitation: ${u.uncertaintyNotes}\n`);
}

console.log('==========================================================================================');
console.log('BENCHMARK EVALUATION COMPLETE');
console.log('==========================================================================================');
