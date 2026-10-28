import { analyzeMessage } from './src/utils/messageAnalyzer';

interface TestCase {
  id: string;
  category: string;
  message: string;
  expectedVerdict: 'SAFE' | 'RISKY' | 'SCAM';
  minScore?: number;
  maxScore?: number;
  expectedFlags?: string[];
  notes: string;
}

const testCases: TestCase[] = [
  // ---------------------------------------------------------
  // 1. SPECIFIED HINGLISH SCAM PHRASES
  // ---------------------------------------------------------
  {
    id: 'HIN-01',
    category: 'Hinglish Fake KYC Request',
    message: 'Aapka khata block ho jayega, turant KYC karein.',
    expectedVerdict: 'RISKY',
    minScore: 40,
    expectedFlags: ['rule_kyc_verification', 'rule_urgency'],
    notes: 'Prompt Example 1: Account closure threat with urgent KYC demand',
  },
  {
    id: 'HIN-02',
    category: 'Hinglish UPI PIN Trap',
    message: 'Paise prapt karne ke liye UPI PIN dalein.',
    expectedVerdict: 'SCAM',
    minScore: 65,
    expectedFlags: ['rule_credentials', 'rule_upi_collect_refund'],
    notes: 'Prompt Example 2: Fake promise to receive money by entering UPI PIN',
  },
  {
    id: 'HIN-03',
    category: 'Hinglish Account Threat & Link',
    message: 'Aapka account band ho jayega, link par click karein.',
    expectedVerdict: 'RISKY',
    minScore: 40,
    expectedFlags: ['rule_kyc_verification', 'rule_urgency'],
    notes: 'Prompt Example 3: Account closure threat with link click directive',
  },
  {
    id: 'HIN-04',
    category: 'Hinglish Utility Cutoff Threat',
    message: 'Bijli connection kat jayega, abhi payment karein.',
    expectedVerdict: 'RISKY',
    minScore: 40,
    expectedFlags: ['rule_utility_cutoff', 'rule_urgency'],
    notes: 'Prompt Example 4: Electricity disconnection threat with immediate payment demand',
  },
  {
    id: 'HIN-05',
    category: 'Hinglish Full Phishing Lure with URL',
    message: 'Aapka khata block ho jayega, turant KYC karein at http://sbi-kyc-update.xyz/login warna account band hoga.',
    expectedVerdict: 'SCAM',
    minScore: 65,
    expectedFlags: ['rule_kyc_verification', 'rule_urgency', 'rule_suspicious_urls'],
    notes: 'Hinglish KYC threat paired with high-risk phishing URL',
  },

  // ---------------------------------------------------------
  // 2. PUNCTUATION & EVASION OBFUSCATION
  // ---------------------------------------------------------
  {
    id: 'OBF-01',
    category: 'Dot-Separated O.T.P',
    message: 'Dear customer, please share your O.T.P to reverse the wrongly deducted transaction.',
    expectedVerdict: 'SCAM',
    minScore: 65,
    expectedFlags: ['rule_credentials', 'rule_upi_collect_refund'],
    notes: 'Dot-separated O.T.P evasion in credential refund scam',
  },
  {
    id: 'OBF-02',
    category: 'Hyphen-Separated O-T-P',
    message: 'Kindly send your O-T-P to verify your account or netbanking will be suspended within 24 hours.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    expectedFlags: ['rule_credentials', 'rule_urgency'],
    notes: 'Hyphen-separated O-T-P evasion with deadline pressure',
  },
  {
    id: 'OBF-03',
    category: 'Underscore-Separated O_T_P',
    message: 'Enter your O_T_P at http://verify-portal.xyz to confirm your lottery reward.',
    expectedVerdict: 'SCAM',
    minScore: 60,
    expectedFlags: ['rule_credentials', 'rule_suspicious_urls'],
    notes: 'Underscore-separated O_T_P in phishing URL lure',
  },
  {
    id: 'OBF-04',
    category: 'Dot-Separated K.Y.C Obfuscation',
    message: 'URGENT: Your bank K.Y.C. has expired. Submit documents now at bit.ly/bank-kyc or card will be permanently blocked.',
    expectedVerdict: 'SCAM',
    minScore: 65,
    expectedFlags: ['rule_kyc_verification', 'rule_urgency', 'rule_suspicious_urls'],
    notes: 'Dot-separated K.Y.C. with trailing dot and shortener link',
  },
  {
    id: 'OBF-05',
    category: 'Dot & Hyphen U.P.I P-I-N Obfuscation',
    message: 'Paise lene ke liye U.P.I P-I-N dalein.',
    expectedVerdict: 'SCAM',
    minScore: 65,
    expectedFlags: ['rule_credentials', 'rule_upi_collect_refund'],
    notes: 'Compound punctuation evasion in Hinglish UPI PIN trap',
  },
  {
    id: 'OBF-06',
    category: 'Dot-Separated M.P.I.N Obfuscation',
    message: 'Please provide your M.P.I.N. to authorize instant refund.',
    expectedVerdict: 'SCAM',
    minScore: 65,
    expectedFlags: ['rule_credentials', 'rule_upi_collect_refund'],
    notes: 'Dot-separated M.P.I.N. with trailing dot in refund scheme',
  },

  // ---------------------------------------------------------
  // 3. LEGITIMATE BENIGN MESSAGES (FALSE POSITIVE CHECKS)
  // ---------------------------------------------------------
  {
    id: 'LEG-01',
    category: 'Hinglish Defensive Bank Advisory',
    message: 'Kripya dhyan dein: Bank kabhi bhi aapse OTP, UPI PIN ya password nahi mangta. Kisi ko bhi apna OTP na batayein.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    notes: 'Authentic Hindi defensive awareness advisory educating users not to share OTP',
  },
  {
    id: 'LEG-02',
    category: 'Hinglish Authentic Bank Debit Alert',
    message: 'Aapke khate XX4321 se INR 450 debited ho gaye hain at Campus Cafeteria on 26-Oct. Agar aapne nahi kiya toh SMS BLOCK to 567676.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    notes: 'Authentic routine banking debit SMS in Romanized Hindi',
  },
  {
    id: 'LEG-03',
    category: 'Hinglish Casual Student Chat',
    message: 'Bhai, kal library chalte hain subah 10 baje. Assignment complete karna hai aur canteen mein chai peeyenge.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    notes: 'Informal student study session plan in Romanized Hindi',
  },
  {
    id: 'LEG-04',
    category: 'Hinglish College Fee Notice',
    message: 'College Notice: Semester fees jama karne ki antim tithi 15 November hai. Office counter par receipt le sakte hain.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    notes: 'Campus academic semester fee deadline notice',
  },
  {
    id: 'LEG-05',
    category: 'Hinglish Electricity Bill Payment Confirmation',
    message: 'Maine bijli ka bill pay kar diya hai official electricity app se, confirmation receipt download kar li hai.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    notes: 'Routine family bill payment confirmation without coercion',
  },
  {
    id: 'LEG-06',
    category: 'English Defensive Bank Warning',
    message: 'SBI Safety Alert: Never share your OTP, PIN or CVV with anyone. Bank officials never ask for sensitive credentials.',
    expectedVerdict: 'SAFE',
    maxScore: 0,
    notes: 'Standard English bank defensive safety advisory',
  },
];

console.log('========================================================================');
console.log('PHASE 3 MESSAGE ANALYZER VERIFICATION SUITE');
console.log('Testing Punctuation Obfuscation, Hinglish Fraud, and Benign Controls');
console.log('========================================================================\n');

let passCount = 0;
let failCount = 0;

for (const t of testCases) {
  try {
    const res = analyzeMessage(t.message);
    const scorePass =
      (t.minScore === undefined || res.score >= t.minScore) &&
      (t.maxScore === undefined || res.score <= t.maxScore);
    const verdictPass = res.verdict === t.expectedVerdict;
    const flagsPass =
      !t.expectedFlags ||
      t.expectedFlags.every((f) => res.warningSigns.some((w) => w.id === f));

    const passed = scorePass && verdictPass && flagsPass;

    if (passed) {
      passCount++;
      console.log(`[PASS] ${t.id} (${t.category})`);
    } else {
      failCount++;
      console.log(`[FAIL] ${t.id} (${t.category})`);
    }

    console.log(`  Message:  "${t.message}"`);
    console.log(`  Verdict:  Expected ${t.expectedVerdict} | Actual ${res.verdict}`);
    console.log(`  Score:    ${res.score} / 100`);
    console.log(`  Flags (${res.warningSigns.length}): ${res.warningSigns.map((w) => w.id).join(', ') || 'None'}`);
    console.log(`  Notes:    ${t.notes}`);
    console.log('------------------------------------------------------------------------');
  } catch (err: any) {
    failCount++;
    console.log(`[ERROR] ${t.id}: ${err.message}`);
    console.log('------------------------------------------------------------------------');
  }
}

console.log(`\nEXECUTION SUMMARY: ${passCount} / ${testCases.length} PASSED (${((passCount / testCases.length) * 100).toFixed(1)}%)`);
console.log('========================================================================');

if (failCount > 0) {
  process.exit(1);
}
