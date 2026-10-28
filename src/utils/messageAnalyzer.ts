/**
 * ScamLens Heuristic Message Analysis Engine
 * Uses explainable deterministic rule heuristics to evaluate messages.
 */

import { MessageAnalysisResult, RiskLevel, WarningSign } from '../types/analyzer';

// Regex to extract all web URLs from message text, including when sender omits https:// or www.
export const URL_REGEX = /(?:(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`\[\]]+|(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|is\.gd|rb\.gy|shorturl\.at|ow\.ly)\/[^\s<>"'{}|\\^`\[\]]+|\b[a-zA-Z0-9-]+\.(?:com|org|net|edu|gov|in|co\.in|ac\.in|edu\.in|gov\.in|net\.in|org\.in|co\.uk|org\.uk|ac\.uk|gov\.uk|xyz|top|tk|ml|ga|cf|gq|buzz|click|work|icu|cam|kim|vip|fit|monster|rest|ly|io|ai|app|dev|me|site|online|live|tech|store|shop|link|info|biz)(?:\/[^\s<>"'{}|\\^`\[\]]*)?)/gi;

/**
 * Helper to de-obfuscate words split by punctuation, spaces, dashes, underscores, or symbols
 * (e.g., O.T.P, O-T-P, O_T_P, O T P, O*T*P, O/T/P, O.T.P.)
 */
function deobfuscateTerm(text: string, letters: string, replacement: string): string {
  const pattern = letters.split('').join('[\\s._*\\/-]+');
  const regex = new RegExp(`(^|[^a-zA-Z0-9])(${pattern}\\.?)(?=[^a-zA-Z0-9]|$)`, 'gi');
  return text.replace(regex, (_match, prefix) => prefix + replacement);
}

/**
 * Normalizes message text for evasion detection (spaced credentials, punctuation obfuscation, zero-width spaces).
 * Crucial: Long patterns (MPIN, PASSWORD) are replaced BEFORE sub-patterns (PIN) to prevent partial replacement bugs.
 */
export function normalizeMessageText(text: string): { original: string; normalized: string } {
  // 1. Remove zero-width characters and invisible format control characters
  let clean = text.replace(/[\u200B-\u200D\uFEFF]/g, '');

  // 2. De-obfuscate punctuation and spaced letter evasion for security terms (e.g., O.T.P, O-T-P, O_T_P)
  clean = deobfuscateTerm(clean, 'PASSWORD', 'PASSWORD');
  clean = deobfuscateTerm(clean, 'MPIN', 'MPIN');
  clean = deobfuscateTerm(clean, 'OTP', 'OTP');
  clean = deobfuscateTerm(clean, 'PIN', 'PIN');
  clean = deobfuscateTerm(clean, 'CVV', 'CVV');
  clean = deobfuscateTerm(clean, 'KYC', 'KYC');
  clean = deobfuscateTerm(clean, 'UPI', 'UPI');
  clean = deobfuscateTerm(clean, 'AADHAAR', 'AADHAAR');
  clean = deobfuscateTerm(clean, 'AADHAR', 'AADHAAR');

  return { original: text, normalized: clean };
}

interface RuleDefinition {
  id: string;
  category: string;
  title: string;
  points: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  match: (text: string, normalized: string, extractedUrls: string[]) => string[] | null;
  explanation: (matched: string[]) => string;
  recommendation: string;
}

const MESSAGE_RULES: RuleDefinition[] = [
  {
    id: 'rule_credentials',
    category: 'Sensitive Credentials',
    title: 'Requests for OTPs, PINs, passwords, or sensitive credentials',
    points: 35,
    severity: 'critical',
    match: (_text, normalized) => {
      // Check if message is merely a defensive warning advising NOT to share OTP
      const isDefensiveAdvisory = (
        /\b(?:do\s+not|never|don't|not\s+to)\s+(?:share|disclose|give|tell|forward|send|submit|enter)\b.{1,40}\b(?:otp|pin|password|mpin|code|credentials|cvv)\b/i.test(normalized) ||
        /\b(?:kisi\s+ko\s+(?:bhi\s+)?(?:apna\s+)?(?:\d+[- ]ankon\s+ka\s+)?(?:otp|pin|mpin|password|cvv)\s+(?:na|mat)\s+(?:batayein|dein|share\s+karein|bhejein)|(?:otp|pin|mpin|password|cvv)\s+(?:kisi\s+ko\s+na\s+dein|kisi\s+se\s+share\s+na\s+karein))\b/i.test(normalized) ||
        /\b(?:bank\s+kabhi\s+(?:bhi\s+)?(?:otp|pin|password|cvv)\s+nahi\s+mangta)\b/i.test(normalized)
      ) && !/(?:share|send|enter|provide|forward|dalein|submit)\s+(?:your\s+|apna\s+)?(?:otp|pin|password|mpin|credentials)\s+(?:to|at|below|link|number|par|yahan|through)/i.test(normalized);

      if (isDefensiveAdvisory) {
        return null;
      }

      const matches: string[] = [];
      const patterns = [
        /(?:submit|submitting|share|sharing|enter|entering|send|sending|provide|providing|give|giving|disclose|disclosing|forward|forwarding|tell|input|inputting|supply|supplying)\b.{1,60}\b(?:otp|one-time\s+passwords?|upi\s+pins?|mpins?|atm\s+pins?|cvvs?|card\s+security\s+codes?|(?:banking\s+|netbanking\s+|online\s+banking\s+|temporary\s+)?passwords?|banking\s+credentials|login\s+credentials|account\s+credentials|secret\s+codes?)\b/i,
        /\b(?:submit|submitting|share|sharing|enter|entering|send|sending|provide|providing|give|giving|disclose|disclosing|forward|forwarding|tell|input|supply)\s+(?:your\s+)?(?:\d+[- ](?:digit|ankon\s+ka)\s+)?(?:otp|pin|cvv|mpin|password|credentials)\b/i,
        /\b(?:banking\s+credentials|netbanking\s+credentials)\s+(?:and|or)\s+(?:otp|pin|mpin|password)\b/i,
        /\b(?:otp|one-time\s+passwords?|upi\s+pins?|mpins?|atm\s+pins?|cvvs?|card\s+security\s+codes?|banking\s+passwords?|banking\s+credentials)\b.{1,40}\b(?:must\s+be\s+|is\s+required\s+to\s+be\s+|to\s+be\s+|needed\s+to\s+be\s+)?(?:submitted|entered|shared|provided|disclosed|forwarded|sent)\b/i,
        /\b(?:upi\s+pin|atm\s+pin|mpin)\s+(?:to\s+receive|to\s+reverse|to\s+claim|to\s+authorize|required)/i,
        /(?:reverse|refund|claim|cancel|authorize).{1,40}(?:share|enter|provide|submit)\s+(?:your\s+)?(?:otp|pin|mpin)/i,
        /\benter\s+(?:your\s+)?(?:upi\s+pin|mpin|atm\s+pin)\b/i,
        // Hinglish credential solicitation patterns:
        /(?:paise|amount|rupaye|dhan|cash|funds?|refund)\s+(?:prapt\s+karne|lene|pane|receive\s+karne)\s+ke\s+liye\s+(?:upi\s+)?(?:pin|mpin|otp)\s*(?:dalein|darj\s+karein|enter\s+karein|lagayein)/i,
        /\b(?:upi\s+pin|atm\s+pin|mpin|otp|password|cvv)\s*(?:dalein|darj\s+karein|enter\s+karein|lagayein|bhejein|batao|batayein|share\s+karein)\b/i,
        /(?:apna|kripya)\s+(?:(?:\d+[- ](?:digit|ankon\s+ka)\s+)?(?:otp|pin|mpin|password))\s*(?:dalein|darj\s+karein|batao|batayein|bhejein|share\s+karein)/i,
      ];

      for (const p of patterns) {
        const m = normalized.match(p);
        if (m && !matches.includes(m[0])) {
          matches.push(m[0]);
        }
      }
      return matches.length > 0 ? matches : null;
    },
    explanation: (matched) =>
      `Detected sensitive credential solicitation (matches: "${matched.slice(0, 3).join('", "')}"). Legitimate banks, services, and colleges will NEVER ask you to disclose OTPs, PINs, or passwords.`,
    recommendation:
      'Never reveal OTPs, PINs, or passwords under any circumstances. Anyone asking for your OTP is attempting unauthorized access to your account or funds.',
  },
  {
    id: 'rule_job_fee',
    category: 'Employment & Scholarship Fees',
    title: 'Upfront job, internship, or scholarship fees',
    points: 30,
    severity: 'high',
    match: (_text, normalized) => {
      const jobContextRegex = /(?:internship|intern\b|job\s+offer|shortlisted|selected\s+for|selected\s+as|hired|recruitment|onboarding\s+kit|developer\s+kit|laptop\s+kit|work\s+from\s+home\s+job|stipend|scholarship|fellowship|grant\s+award)/i;
      const feeDemandRegex = /(?:registration\s+(?:fees?|charges?)|processing\s+(?:fees?|charges?)|security\s+deposits?|onboarding\s+(?:fees?|charges?|deposits?)|kit\s+(?:fee|charge|deposit)s?|laptop\s+(?:deposits?|charges?)|training\s+charges?|refundable\s+(?:onboarding\s+|security\s+)?deposits?|documentation\s+(?:fees?|charges?)|disbursement\s+fees?|claim\s+fees?|(?:pay|transfer|deposit)\s+(?:a\s+)?(?:refundable\s+)?(?:fee|deposit|charge|amount)?\s*(?:of\s+)?(?:rs\.?|inr|₹|\$)\s*\d+)/i;

      const hasJobContext = jobContextRegex.test(normalized);
      const hasFeeDemand = feeDemandRegex.test(normalized);

      // Protect legitimate academic notices (symposiums, college seminars, sports meets) without employment context
      const isAcademicNoticeOnly = /(?:symposium|seminar|workshop|conference|hackathon|fest|sports\s+meet|club\s+meeting|department\s+counter|exam\s+fee|tuition\s+fee)/i.test(
        normalized
      ) && !hasJobContext;

      if (isAcademicNoticeOnly) {
        return null;
      }

      if (hasJobContext && hasFeeDemand) {
        const matched: string[] = [];
        const feeMatch = normalized.match(feeDemandRegex);
        if (feeMatch) matched.push(feeMatch[0]);
        const jobMatch = normalized.match(jobContextRegex);
        if (jobMatch) matched.push(jobMatch[0]);
        return matched;
      }

      const combinedMatch = normalized.match(/\b(?:shortlisted|selected|awarded)\b.{1,60}\b(?:pay|deposit|fee|charge)\b/i);
      if (combinedMatch) {
        return [combinedMatch[0]];
      }

      return null;
    },
    explanation: (matched) =>
      `Detected upfront recruitment, registration, or scholarship fee demands (matches: "${matched.slice(0, 3).join('", "')}"). Legitimate employers and genuine scholarship programs never charge students an application, processing, or disbursement fee.`,
    recommendation:
      'Legitimate companies and scholarship providers award or pay money for work and merit—they never ask you to pay advance fees. Any internship or scholarship requesting registration or processing fees is fraudulent.',
  },
  {
    id: 'rule_upi_collect_refund',
    category: 'UPI Refund / Collect Traps',
    title: 'UPI collect or fraudulent refund requests',
    points: 30,
    severity: 'critical',
    match: (_text, normalized) => {
      const matches: string[] = [];
      const patterns = [
        /\b(?:upi\s+collect|approve\s+collect|accept\s+collect|reverse\s+collect|pending\s+collect\s+request)\b/i,
        /\b(?:sent\s+by\s+mistake|wrongly\s+credited|wrongly\s+deducted|accidentally\s+sent|excess\s+amount\s+sent|sent\s+rs\.?\s*\d+\s+extra)\b/i,
        /\b(?:reverse\s+(?:the\s+)?(?:amount|transaction|debit|payment)|refund\s+back|money\s+wrongly\s+sent|reverse\s+refund)\b/i,
        /\b(?:enter\s+(?:upi\s+)?pin\s+to\s+receive|enter\s+pin\s+to\s+claim|approve\s+the\s+collect\s+request|enter\s+your\s+upi\s+pin\s+to\s+process|authorize\s+(?:the\s+)?(?:pending\s+|instant\s+)?refund)\b/i,
        /\b(?:open\s+(?:phonepe|gpay|google\s+pay|paytm)\s+and\s+(?:approve|accept|enter\s+pin))\b/i,
        // Hinglish UPI collect / refund trap patterns:
        /\b(?:paise|amount|rupaye|dhan|funds?)\s+(?:prapt\s+karne|lene|pane|receive\s+karne)\s+ke\s+liye\s+(?:upi\s+)?(?:pin|mpin)\s*(?:dalein|darj\s+karein|enter\s+karein|lagayein)?\b/i,
        /\b(?:galti\s+se\s+(?:paise|rupaye|amount)\s+(?:chale\s+gaye|bhej\s+diye|transfer\s+ho\s+gaye)|extra\s+(?:paise|amount)\s+bhej\s+diye)\b/i,
        /\b(?:paise\s+wapas\s+karne|refund\s+paane|refund\s+lene)\s+ke\s+liye\s+(?:collect\s+request\s+accept\s+karein|pin\s+dalein)\b/i,
        /\b(?:phonepe|gpay|google\s+pay|paytm)\s+khol\s*kar\s+(?:collect\s+request\s+accept\s+karein|pin\s+dalein)\b/i,
      ];

      for (const p of patterns) {
        const m = normalized.match(p);
        if (m && !matches.includes(m[0])) {
          matches.push(m[0]);
        }
      }
      return matches.length > 0 ? matches : null;
    },
    explanation: (matched) =>
      `Detected UPI collect or refund deception (matches: "${matched.slice(0, 3).join('", "')}"). Scammers pretend to have sent excess money and trick victims into approving a "collect" request or entering their PIN to "receive" funds.`,
    recommendation:
      'Fundamental UPI rule: Entering your UPI PIN ALWAYS deducts money from your account. You NEVER need to enter your PIN or accept a collect request to receive money.',
  },
  {
    id: 'rule_social_engineering_coercion',
    category: 'Impersonation & Legal Coercion',
    title: 'Digital arrest, police, court, or statutory authority coercion',
    points: 30,
    severity: 'critical',
    match: (_text, normalized) => {
      const hasAuthority = /(?:supreme\s+court|high\s+court|cbi|police\s+(?:officer|station|department)|narcotics|customs\s+department|cyber\s+crime\s+branch|trai|income\s+tax\s+department)/i.test(
        normalized
      );
      const hasCoercion = /(?:arrest\s+warrant|money\s+laundering|seized|illegal\s+parcel|video\s+call\s+verification|stay\s+on\s+(?:the\s+)?call|do\s+not\s+inform\s+anyone|keep\s+this\s+confidential|pay\s+(?:fine|penalty|bail)|under\s+digital\s+arrest)/i.test(
        normalized
      );

      if (hasAuthority && hasCoercion) {
        const matches: string[] = [];
        const m1 = normalized.match(/(?:supreme\s+court|cbi|police|narcotics|customs|trai)/i);
        if (m1) matches.push(m1[0]);
        const m2 = normalized.match(/(?:arrest\s+warrant|money\s+laundering|video\s+call|do\s+not\s+inform|pay\s+fine|digital\s+arrest)/i);
        if (m2) matches.push(m2[0]);
        return matches;
      }
      return null;
    },
    explanation: (matched) =>
      `Detected high-pressure statutory authority or police impersonation (matches: "${matched.slice(0, 3).join('", "')}"). Law enforcement and judicial bodies NEVER conduct trials over Skype/WhatsApp or demand financial transfers to avoid "digital arrest".`,
    recommendation:
      'Do not comply with demands to transfer money or remain on continuous video calls. Law enforcement agencies never arrest people digitally over video calls.',
  },
  {
    id: 'rule_apk_installation',
    category: 'Malicious Software & APKs',
    title: 'Unknown APK installation or remote control app requests',
    points: 30,
    severity: 'critical',
    match: (_text, normalized) => {
      const matches: string[] = [];
      const patterns = [
        /\.apk\b/i,
        /\b(?:download\s+(?:the\s+)?apk|install\s+(?:this\s+)?apk|sideload|install\s+update\s+file)\b/i,
        /\b(?:anydesk|teamviewer|quicksupport|rustdesk|screen\s*share|airdroid)\b/i,
        /\b(?:install\s+support\s+app|download\s+verification\s+app|remote\s+access\s+app)\b/i,
      ];

      for (const p of patterns) {
        const m = normalized.match(p);
        if (m && !matches.includes(m[0])) {
          matches.push(m[0]);
        }
      }
      return matches.length > 0 ? matches : null;
    },
    explanation: (matched) =>
      `Detected sideloaded APK or remote control software solicitation (matches: "${matched.slice(0, 3).join('", "')}"). Malicious APKs read OTP SMS messages and remote control tools allow attackers to drain bank balances.`,
    recommendation:
      'Never download APK files sent over messages or chat apps. Only install verified applications from official app stores like Google Play Store or Apple App Store.',
  },
  {
    id: 'rule_kyc_verification',
    category: 'Unverified KYC & Account Threats',
    title: 'Unverified KYC or bank verification requests',
    points: 25,
    severity: 'high',
    match: (_text, normalized) => {
      const matches: string[] = [];
      const patterns = [
        /\b(?:kyc\s+(?:(?:has|is)\s+)?(?:expired|update|verification|pending|incomplete)|update\s+kyc)\b/i,
        /\b(?:(?:bank\s+|user\s+)?account|debit\s+card|credit\s+card|card|netbanking(?:\s+account|\s+access)?)\s+(?:has\s+been\s+(?:flagged\s+for\s+)?|will\s+be\s+|is\s+)?(?:permanently\s+|temporarily\s+)?(?:flagged\s+for\s+suspension|suspension|blocked|dormant|frozen|suspended|disabled|deactivated|closed|terminated)\b/i,
        /\b(?:to\s+prevent|avoid)\s+(?:account\s+)?(?:suspension|closure|blocking|deactivation|termination)\b/i,
        /\b(?:account\s+suspension|suspension\s+of\s+(?:your\s+)?(?:bank\s+)?account)\b/i,
        /\b(?:unusual|suspicious|unauthorized)\s+activity\s+(?:has\s+been\s+)?(?:detected|noticed|observed|found)\b/i,
        /\b(?:result\s+in\s+|lead\s+to\s+)?(?:restricted|limited)\s+access\b/i,
        /\b(?:verification\s+portal|verification\s+link|security\s+portal|kyc\s+portal)\b/i,
        /\bverify\s+(?:your\s+)?(?:identity|account)\b.{1,50}\b(?:portal|link|credentials|otp|immediately)\b/i,
        /\bcomplete\s+(?:your\s+)?(?:kyc|verification)\s+(?:using|at|via|through)\b/i,
        /\b(?:aadhaar|pan\s+card|pan\s+link|link\s+aadhaar\s+pan|unlinked\s+pan)\b.{1,50}\b(?:block|suspend|update|verify|frozen|deactivation)\b/i,
        /\b(?:submit\s+(?:your\s+)?documents\s+(?:now\s+)?at|click\s+here\s+to\s+verify\s+kyc|account\s+access\s+has\s+been\s+restricted)\b/i,
        /\b(?:sbi|hdfc|icici|axis|pnb)\s+account\s+is\s+(?:blocked|frozen)\b/i,
        // Hinglish fake KYC & account closure threat patterns:
        /\b(?:aapka\s+)?(?:khata|account)\s+(?:block|band|freeze|rok|suspend)\s*(?:ho\s*jayega|ho\s*gaya|kar\s*diya\s*jayega|hoga)\b/i,
        /\b(?:turant|abhi|fauran|jald)\s+(?:kyc|pan|aadhaar)\s*(?:karein|karayein|update\s+karein|verify\s+karein|karwayen|karlein|complete\s+karein)\b/i,
        /\b(?:kyc|pan|aadhaar)\s*(?:karein|karayein|karwayen|update\s+karein|adatan\s+karein|pura\s+karein)\b/i,
        /\b(?:link\s+par\s+click\s+karein|link\s+kholein|link\s+par\s+jayein)\b/i,
        /\b(?:khata|account)\s+(?:chalu\s+rakhne|unblock\s+karne|bachane)\s+ke\s+liye\b/i,
      ];

      for (const p of patterns) {
        const m = normalized.match(p);
        if (m && !matches.includes(m[0])) {
          matches.push(m[0]);
        }
      }
      return matches.length > 0 ? matches : null;
    },
    explanation: (matched) =>
      `Detected unverified KYC or banking threat prompts (matches: "${matched.slice(0, 3).join('", "')}"). Banks never send text messages threatening account closure and demanding document submission via third-party links.`,
    recommendation:
      'If you receive a message about bank KYC or account blocking, do not follow link instructions. Call your official bank customer care number printed on your debit card or visit your local branch.',
  },
  {
    id: 'rule_utility_cutoff',
    category: 'Utility & Service Disconnection Threats',
    title: 'Electricity or essential service cutoff threats',
    points: 25,
    severity: 'high',
    match: (_text, normalized) => {
      const matches: string[] = [];
      const patterns = [
        /(?:electricity|power|power\s+supply|power\s+meter|power\s+connection|water\s+supply)\s+(?:meter\s+)?(?:will\s+be\s+)?(?:disconnected|cutoff|cut\s+off|suspended)/i,
        /(?:unpaid\s+electricity\s+bill|unpaid\s+balance|due\s+to\s+non-payment\s+of\s+bill|previous\s+month\s+bill\s+not\s+updated)/i,
        /(?:call|contact)\s+(?:our\s+|the\s+)?(?:electricity|power)\s+(?:officer|department|executive)/i,
        // Hinglish utility cutoff extortion patterns:
        /(?:bijli|electricity|power|light|meter)\s+(?:connection\s+)?(?:kat\s+jayega|kaat\s+diya\s+jayega|cut\s+jayega|band\s+ho\s+jayega|disconnect\s+ho\s+jayega)/i,
        /(?:bijli|light|electricity)\s+(?:bill|bhugtan)\s+(?:baki\s+hai|jama\s+nahi\s+hua|unpaid\s+hai|nahi\s+bhara)/i,
        /(?:bijli|power|light)\s+(?:officer|adhikari|department)\s+(?:se\s+sampark\s+karein|ko\s+call\s+karein)/i,
        /(?:bijli\s+katne\s+se\s+bachane\s+ke\s+liye|turant\s+bijli\s+bill\s+bharein)/i,
      ];

      for (const p of patterns) {
        const m = normalized.match(p);
        if (m && !matches.includes(m[0])) {
          matches.push(m[0]);
        }
      }
      return matches.length > 0 ? matches : null;
    },
    explanation: (matched) =>
      `Detected fraudulent utility/electricity disconnection threats (matches: "${matched.slice(0, 3).join('", "')}"). Electricity boards never send personal SMS messages threatening same-night disconnection with personal mobile numbers to contact.`,
    recommendation:
      'Never call personal mobile numbers sent in electricity warning messages. Verify your bill status directly on your official state electricity board portal or authorized consumer app.',
  },
  {
    id: 'rule_courier_fee',
    category: 'Courier & Package Redelivery Traps',
    title: 'Fake courier delivery failure and fee demands',
    points: 25,
    severity: 'high',
    match: (_text, normalized) => {
      const matches: string[] = [];
      const patterns = [
        /(?:parcel|package|shipment|courier|consignment|order\s+#\d+)\s+(?:cannot\s+be\s+delivered|could\s+not\s+be\s+delivered|on\s+hold|delivery\s+failed|incomplete\s+address|invalid\s+house\s+number|pending\s+delivery)/i,
        /(?:update\s+(?:delivery\s+)?address|reschedule\s+delivery|redelivery\s+fee)\b.{1,40}(?:link|fee|pay|charge|http)/i,
      ];

      for (const p of patterns) {
        const m = normalized.match(p);
        if (m && !matches.includes(m[0])) {
          matches.push(m[0]);
        }
      }
      return matches.length > 0 ? matches : null;
    },
    explanation: (matched) =>
      `Detected fake courier delivery failure or package address redelivery fee demands (matches: "${matched.slice(0, 3).join('", "')}"). Postal services like India Post or FedEx do not demand fee payments via unsolicited text links to complete standard deliveries.`,
    recommendation:
      'Do not pay redelivery fees or click links in delivery SMS messages. Track your parcel exclusively on the official postal or courier website using your original tracking number.',
  },
  {
    id: 'rule_loan_advance_fee',
    category: 'Predatory Loan Traps',
    title: 'Instant pre-approved loan with upfront processing fees',
    points: 25,
    severity: 'high',
    match: (_text, normalized) => {
      const hasLoanOffer = /(?:pre-approved\s+(?:instant\s+)?(?:cash\s+)?loan|pre-approved\s+student\s+education\s+loan|instant\s+loan|instant\s+cash\s+loan|loan\s+approved|sanctioned\s+loan|loan\s+of\s+(?:rs\.?|inr|₹|\$)\s*\d+)/i.test(normalized);
      const hasUpfrontFee = /(?:processing\s+fees?|file\s+charges?|file\s+processing\s+charges?|insurance\s+fees?|disbursement\s+charges?|documentation\s+charges?|pay\s+(?:rs\.?|inr|₹|\$)\s*\d+|transfer\s+(?:rs\.?|inr|₹|\$)\s*\d+)/i.test(normalized);

      if (hasLoanOffer && hasUpfrontFee) {
        const matches: string[] = [];
        const m1 = normalized.match(/(?:pre-approved\s+(?:instant\s+)?(?:cash\s+)?loan|pre-approved\s+student|instant\s+loan|loan\s+approved)/i);
        if (m1) matches.push(m1[0]);
        const m2 = normalized.match(/(?:processing\s+fees?|file\s+charges?|file\s+processing\s+charges?|documentation\s+charges?)/i);
        if (m2) matches.push(m2[0]);
        return matches;
      }
      return null;
    },
    explanation: (matched) =>
      `Detected predatory loan advance-fee scheme (matches: "${matched.slice(0, 3).join('", "')}"). Legitimate banks and regulated lenders deduct fees from the disbursed loan amount; they never ask borrowers to transfer upfront advance fees.`,
    recommendation:
      'Never transfer money to "unlock" or receive a loan. Only apply for loans through RBI-licensed banking apps or physical branches.',
  },
  {
    id: 'rule_off_platform_redirection',
    category: 'Off-Platform Redirection',
    title: 'Directing communication away to unauthorized chat channels',
    points: 15,
    severity: 'medium',
    match: (_text, normalized) => {
      const matches: string[] = [];
      const patterns = [
        /(?:contact|message|chat|reach|dm)\s+(?:our\s+)?(?:hr|recruitment|recruiter|officer|manager|agent|team)?\s*(?:on|via)\s+(?:whatsapp|telegram)\b/i,
        /\b(?:join\s+(?:our\s+)?telegram\s+channel\s+to\s+earn|dm\s+on\s+telegram|message\s+on\s+whatsapp\s+to\s+claim|dm\s+(?:our\s+)?recruitment\s+team\s+on\s+telegram)\b/i,
        /\b(?:wa\.me|t\.me)\/[a-zA-Z0-9_]+/i,
      ];

      for (const p of patterns) {
        const m = normalized.match(p);
        if (m && !matches.includes(m[0])) {
          matches.push(m[0]);
        }
      }
      return matches.length > 0 ? matches : null;
    },
    explanation: (matched) =>
      `Detected redirection to unverified private chat platforms (matches: "${matched.slice(0, 3).join('", "')}"). Scammers use Telegram and WhatsApp to evade organizational monitoring and identity verification.`,
    recommendation:
      'Do not conduct official recruitment or financial business over informal personal Telegram or WhatsApp accounts. Always communicate via official company email domains.',
  },
  {
    id: 'rule_suspicious_urls',
    category: 'Suspicious Web Links',
    title: 'Suspicious or shortened links in message',
    points: 25,
    severity: 'high',
    match: (_text, normalized, extractedUrls) => {
      const matches: string[] = [];
      const shortenerRegex = /(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|is\.gd|rb\.gy|shorturl\.at|ow\.ly)\b/i;
      const disposableTldRegex = /\b(?:https?:\/\/|www\.)?[a-zA-Z0-9-.]+\.(?:xyz|top|tk|ml|ga|cf|gq|buzz|click|work|icu|cam|kim|vip|fit|shop|monster)\b/i;
      const rawIpRegex = /\b(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s]*)?\b/i;

      // Check extracted URLs
      for (const url of extractedUrls) {
        if (shortenerRegex.test(url) || disposableTldRegex.test(url) || rawIpRegex.test(url)) {
          matches.push(url);
        }
      }

      // Check in normalized text
      if (matches.length === 0) {
        const m1 = normalized.match(shortenerRegex);
        if (m1) matches.push(m1[0]);
        const m2 = normalized.match(disposableTldRegex);
        if (m2 && !matches.includes(m2[0])) matches.push(m2[0]);
        const m3 = normalized.match(rawIpRegex);
        if (m3 && !matches.includes(m3[0])) matches.push(m3[0]);
      }

      // Lure pattern "at link to receive"
      if (matches.length === 0 && /\bat\s+link\b/i.test(normalized)) {
        matches.push('at link');
      }

      return matches.length > 0 ? matches : null;
    },
    explanation: (matched) =>
      `Detected high-risk links or URL shorteners (matches: "${matched.slice(0, 2).join('", "')}"). These obscure destinations or masquerade as authentic institutions using alternative domains.`,
    recommendation:
      'Do not click shortened or misspelled links in messages. Always type official URLs directly into your browser address bar or use official mobile apps.',
  },
  {
    id: 'rule_unrealistic_rewards',
    category: 'Unrealistic Guaranteed Rewards',
    title: 'Unrealistic guaranteed rewards or lottery winnings',
    points: 25,
    severity: 'medium',
    match: (_text, normalized) => {
      const matches: string[] = [];
      const patterns = [
        /\b(?:congratulations|you\s+have\s+won|lottery\s+winner|lucky\s+draw|cash\s+prize|bumper\s+cash\s+prize)\b/i,
        /\b(?:guaranteed\s+(?:earnings|income|returns?|profit)|earn\s+(?:rs\.?|inr|₹|\$)\s*[\d,]+(?:\s+to\s+(?:rs\.?|inr|₹|\$)?\s*[\d,]+)?\s*(?:daily|per\s+day))\b/i,
        /\b(?:work\s+from\s+home\s+(?:task\s+job|earn)|like\s+youtube\s+videos|rate\s+google\s+maps|reviewing\s+google\s+play\s+apps|crypto\s+bonus|free\s+recharge)\b/i,
        // Hinglish & Romanized Hindi task scam & video-liking patterns:
        /(?:youtube\s+videos?|videos?|channels?|insta(?:gram)?\s+posts?)\s+(?:like|subscribe|follow)\s*karke/i,
        /(?:like|subscribe|follow)\s+(?:youtube\s+videos?|channels?|insta(?:gram)?\s+posts?)\s*karke/i,
        /(?:online\s+task|work\s+from\s+home\s+task|simple\s+tasks?|daily\s+tasks?).{1,50}(?:paise|rupaye|income|kamayein)/i,
        /(?:rozana|daily|har\s+din)\s+(?:rs\.?|inr|₹|\$)?\s*[\d,]+\s*(?:rupaye|paise|inr)?\s*kamayein/i,
        /(?:ghar\s+baithe|online\s+task)\s+(?:paise|rupaye|income)\s*kamayein/i,
        /\b(?:claim\s+(?:your\s+)?bonus|double\s+your\s+money|instant\s+reward|easy\s+money|receive\s+laptop)\b/i,
      ];

      for (const p of patterns) {
        const m = normalized.match(p);
        if (m && !matches.includes(m[0])) {
          matches.push(m[0]);
        }
      }
      return matches.length > 0 ? matches : null;
    },
    explanation: (matched) =>
      `Detected unrealistic reward or guaranteed return promises (matches: "${matched.slice(0, 3).join('", "')}"). Task scams promising daily money for simple clicks or unsolicited lottery prizes are fraudulent traps.`,
    recommendation:
      'If an offer sounds too good to be true, it is. Nobody gives away free money, laptops, or thousands of rupees per day for liking videos or rating maps.',
  },
  {
    id: 'rule_urgency',
    category: 'Urgency & Coercive Pressure',
    title: 'Urgent pressure and artificial deadlines',
    points: 15,
    severity: 'medium',
    match: (_text, normalized) => {
      const matches: string[] = [];
      const patterns = [
        /\b(?:urgent(?:ly)?|immediate(?:ly)?|act\s+fast|rush|hurry|final\s+notice|last\s+chance)\b/i,
        /\b(?:within|in)\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)\b/i,
        /\b(?:today\s+only|before\s+midnight)\b/i,
        /\bfailure\s+to\s+(?:complete|verify|update|comply|respond)\b/i,
        /\b(?:immediately|urgently)\s+to\s+(?:restore|regain|maintain)\b/i,
        /\b(?:account\s+will\s+be\s+(?:blocked|suspended|terminated|deactivated)|service\s+will\s+stop|permanently\s+suspended|complete\s+deactivation)\b/i,
        /\b(?:immediate\s+action\s+required|card\s+will\s+be\s+permanently\s+suspended)\b/i,
        // Hinglish urgency & pressure patterns:
        /\b(?:turant|abhi\s+ke\s+abhi|abhi\s+payment\s+karein|turant\s+payment\s+karein|fauran|jald\s+se\s+jald|bina\s+der\s+kiye|aaj\s+hi|aaj\s+raat\s+tak|antim\s+chetavni)\b/i,
        /\b(?:khata|account|connection|meter|line)\s+(?:block|band|kat)\s*(?:ho\s*jayega|kar\s*diya\s*jayega)\b/i,
        /\b(?:nahi\s+to|warna)\s+(?:khata|account|connection|sewa)\s+(?:band|block|kat)\b/i,
      ];

      for (const p of patterns) {
        const m = normalized.match(p);
        if (m && !matches.includes(m[0])) {
          matches.push(m[0]);
        }
      }
      return matches.length > 0 ? matches : null;
    },
    explanation: (matched) =>
      `Detected artificial urgency and panic triggers (matches: "${matched.slice(0, 3).join('", "')}"). Scammers artificially compress time to induce anxiety and prevent verification.`,
    recommendation:
      'Take a breath and pause. High-pressure threats of immediate suspension or instant expiration are designed to make you act rashly without verifying.',
  },
];

/**
 * Extracts all URLs from the provided text, including links missing https:// or www.
 */
export function extractUrlsFromText(text: string): string[] {
  const matches = text.match(URL_REGEX) || [];
  const uniqueUrls: string[] = [];
  for (const match of matches) {
    // Strip trailing punctuation often adjacent to URLs in natural prose
    const cleaned = match.replace(/[.,;:!?)\"'>\]]+$/, '');
    if (
      cleaned &&
      !uniqueUrls.includes(cleaned) &&
      cleaned.includes('.') &&
      /[a-zA-Z]/.test(cleaned) &&
      !/^(?:e\.g|i\.e|etc|vs)\.?$/i.test(cleaned)
    ) {
      uniqueUrls.push(cleaned);
    }
  }
  return uniqueUrls;
}

/**
 * Analyzes a given message using explainable heuristic rules.
 */
export function analyzeMessage(text: string): MessageAnalysisResult {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error('Please enter or paste a message to analyze.');
  }

  // Guard against excessively long messages
  const safeText = trimmed.length > 10000 ? trimmed.slice(0, 10000) : trimmed;

  const { normalized } = normalizeMessageText(safeText);
  const words = safeText.split(/\s+/).filter(Boolean);
  const detectedWarnings: WarningSign[] = [];
  const extractedUrls = extractUrlsFromText(safeText);

  let rawScore = 0;

  // Run through each rule category. Each category scores at most ONCE.
  for (const rule of MESSAGE_RULES) {
    const matchedSnippets = rule.match(safeText, normalized, extractedUrls);

    if (matchedSnippets && matchedSnippets.length > 0) {
      rawScore += rule.points;
      detectedWarnings.push({
        id: rule.id,
        category: rule.category,
        title: rule.title,
        points: rule.points,
        explanation: rule.explanation(matchedSnippets),
        matchedSnippets,
        recommendation: rule.recommendation,
        severity: rule.severity,
      });
    }
  }

  // Cap score strictly at 100
  const finalScore = Math.min(100, Math.max(0, rawScore));

  // Determine Verdict based on specified thresholds:
  // 0–24: SAFE, 25–59: RISKY, 60–100: SCAM
  let verdict: RiskLevel = 'SAFE';
  let verdictSummary = 'No prominent scam indicators were detected in this message.';

  if (finalScore >= 60) {
    verdict = 'SCAM';
    verdictSummary =
      'High probability of fraudulent activity. This message exhibits multiple critical red flags typical of financial and identity theft scams.';
  } else if (finalScore >= 25) {
    verdict = 'RISKY';
    verdictSummary =
      'Suspicious warning signs detected. Exercise extreme caution and independently verify the sender through trusted official channels before acting.';
  } else {
    verdict = 'SAFE';
    verdictSummary =
      'Low heuristic risk detected based on standard fraud patterns. However, always exercise personal vigilance with unsolicited communications.';
  }

  // Collect unique recommendations
  const recommendations: string[] = [];
  if (detectedWarnings.length > 0) {
    detectedWarnings.forEach((w) => {
      if (!recommendations.includes(w.recommendation)) {
        recommendations.push(w.recommendation);
      }
    });
  } else {
    recommendations.push(
      'Verify the sender identity directly using official student portals or authorized phone numbers.',
      'Never send personal identity details or pay money based solely on digital messages.',
      'If in doubt, consult your college administration or cybersecurity cell.'
    );
  }

  return {
    score: finalScore,
    verdict,
    verdictSummary,
    warningSigns: detectedWarnings,
    recommendations,
    extractedUrls,
    totalAnalyzedWords: words.length,
    analysisTimestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
  };
}
