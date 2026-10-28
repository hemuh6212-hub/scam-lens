import { analyzeUrl } from './src/utils/urlAnalyzer';

const cases = [
  { id: 'Case A', url: 'http://hdfcbank-verify-kyc.xyz/login.php', desc: 'HDFC Bank concatenation on high-risk TLD with HTTP and phishing keywords' },
  { id: 'Case B', url: 'http://sbibank-kyc-example.xyz/verify', desc: 'SBI concatenation on high-risk TLD with HTTP and verify keyword' },
  { id: 'Case C', url: 'http://icicibank-login-example.xyz/', desc: 'ICICI Bank concatenation on high-risk TLD with HTTP and login keyword' },
  { id: 'Case D', url: 'https://www.hdfcbank.com/', desc: 'Official HDFC Bank domain on HTTPS' },
  { id: 'Case E', url: 'https://sbi.bank.in/', desc: 'Official SBI domain on .bank.in registry' },
  { id: 'Case F', url: 'https://mybankexample.com/', desc: 'Unrelated domain containing generic term "bank"' },
  { id: 'Case G', url: 'https://example.com/hdfc-login', desc: 'Brand term only in URL path, not in hostname' },
  { id: 'Case H', url: 'https://www.google.com/', desc: 'Well-known legitimate site under standard HTTPS' },
];

console.log('========================================================================');
console.log('VERIFICATION TEST RUNNER: CASES A THROUGH H');
console.log('========================================================================\n');

for (const c of cases) {
  try {
    const res = analyzeUrl(c.url);
    console.log(`------------------------------------------------------------------------`);
    console.log(`[${c.id}] ${c.url}`);
    console.log(`Description:   ${c.desc}`);
    console.log(`Verdict:       ${res.verdict}`);
    console.log(`Score:         ${res.riskScore} / 100`);
    console.log(`Hostname:      ${res.hostname}`);
    console.log(`Root Domain:   ${res.rootDomain}`);
    console.log(`Flags (${res.flags.length}):`);
    for (const f of res.flags) {
      console.log(`  - [${f.severity.toUpperCase()}] ${f.id}: ${f.name}`);
    }
  } catch (err: any) {
    console.log(`[${c.id}] ERROR: ${err.message}`);
  }
}

console.log('\n========================================================================');
