import React from 'react';
import { Cpu, ShieldAlert, Lock, CheckCircle, ArrowRight } from 'lucide-react';

export const HowItWorks: React.FC = () => {
  const steps = [
    {
      step: '01',
      title: 'Local Lexical Parsing',
      description:
        'When you submit text, ScamLens tokenizes words, extracted web links, and behavioral phrasing directly in browser memory without sending a single byte over the network.',
    },
    {
      step: '02',
      title: 'Explainable Rule Evaluation',
      description:
        'The engine tests against documented cybersecurity categories (credential requests, internship registration fees, UPI refund traps, APK downloads, utility & delivery traps, and urgency pressures).',
    },
    {
      step: '03',
      title: 'Deduplicated Category Scoring',
      description:
        'Points are added once per threat category (preventing inflated repeated triggers) and capped at 100. Verdicts map deterministically to SAFE (0–24), RISKY (25–59), or SCAM (60–100).',
    },
    {
      step: '04',
      title: 'Actionable Student Advisory',
      description:
        'Rather than vague generic warnings, ScamLens provides clear operational next steps (e.g., how UPI PINs work, how to verify official college notice boards, and national reporting helplines).',
    },
  ];

  const rulesTable = [
    {
      rule: 'Requests for OTPs, PINs, passwords, or credentials',
      pts: '+35 pts',
      rationale: 'Legitimate institutions never request authentication secrets over text or chat.',
    },
    {
      rule: 'Upfront job or internship registration fees',
      pts: '+30 pts',
      rationale: 'Real employers pay interns; demanding payment for onboarding kits is fraud.',
    },
    {
      rule: 'UPI collect or fraudulent refund traps',
      pts: '+30 pts',
      rationale: 'Entering a UPI PIN transfers funds out of your account; you never enter a PIN to receive money.',
    },
    {
      rule: 'Unknown APK installation requests',
      pts: '+30 pts',
      rationale: 'Sideloaded Android APKs intercept incoming SMS OTPs and grant remote access.',
    },
    {
      rule: 'Unverified KYC or bank account blocking threats',
      pts: '+25 pts',
      rationale: 'Banks never threaten immediate closure via SMS links. Verification occurs via official apps.',
    },
    {
      rule: 'Utility or power disconnection threats',
      pts: '+25 pts',
      rationale: 'Electricity boards do not send personal SMS messages threatening same-night disconnection.',
    },
    {
      rule: 'Fake courier delivery failure or package fees',
      pts: '+25 pts',
      rationale: 'Postal carriers do not demand redelivery fee payments via unsolicited text links.',
    },
    {
      rule: 'Predatory loan advance fees & file charges',
      pts: '+25 pts',
      rationale: 'Regulated lenders deduct fees from disbursed loans; they never demand advance transfers.',
    },
    {
      rule: 'Digital arrest or law enforcement coercion',
      pts: '+30 pts',
      rationale: 'Police and courts never conduct trials via video calls or demand bail via money transfers.',
    },
    {
      rule: 'Off-platform redirection to unverified chat',
      pts: '+15 pts',
      rationale: 'Directing victims to Telegram/WhatsApp evades organizational monitoring and identity verification.',
    },
    {
      rule: 'Suspicious URLs or obscured shorteners',
      pts: '+20 pts',
      rationale: 'Abused TLDs (.xyz, .top) and shorteners hide the destination server.',
    },
    {
      rule: 'Unrealistic guaranteed rewards or tasks',
      pts: '+20 pts',
      rationale: 'Schemes paying thousands daily for clicking YouTube videos or map reviews are task scams.',
    },
    {
      rule: 'Urgent pressure and artificial deadlines',
      pts: '+15 pts',
      rationale: 'High-pressure deadlines prevent rational cross-verification with campus authorities.',
    },
  ];

  return (
    <section id="how-it-works" className="py-16 lg:py-24 bg-[#0A1128] border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="max-w-3xl mb-12">
          <div className="text-xs font-semibold text-teal-400 tracking-wider uppercase mb-2">
            Architecture & Transparency
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight text-balance">
            How ScamLens Protects You: Explainable Cybersecurity Rules
          </h2>
          <p className="mt-2 text-sm sm:text-base text-slate-300">
            Unlike "black box" systems, ScamLens uses transparent, deterministic rules based on verified student fraud patterns. Every point in your risk score is explicitly attributed to a specific warning sign.
          </p>
        </div>

        {/* 4 Process Steps */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
          {steps.map((item) => (
            <div
              key={item.step}
              className="p-6 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors space-y-3"
            >
              <div className="text-2xl font-extrabold font-mono text-teal-400">{item.step}.</div>
              <h3 className="text-base font-bold text-white">{item.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{item.description}</p>
            </div>
          ))}
        </div>

        {/* Scoring Matrix Breakdown Table */}
        <div className="bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden shadow-xl">
          <div className="p-6 border-b border-slate-800 bg-slate-950/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-bold text-white">Heuristic Scoring Weight Matrix</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Each warning category contributes points only once. Total score is bounded between 0 and 100.
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <span className="w-2 h-2 rounded-full bg-teal-400" />
              <span>Cap: 100 max points</span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3.5 px-6 font-semibold">Warning Sign / Threat Category</th>
                  <th className="py-3.5 px-4 font-semibold text-right">Points</th>
                  <th className="py-3.5 px-6 font-semibold hidden sm:table-cell">Cybersecurity Rationale</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {rulesTable.map((row, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3.5 px-6 font-medium text-slate-200">{row.rule}</td>
                    <td className="py-3.5 px-4 font-mono font-bold text-teal-400 text-right whitespace-nowrap">
                      {row.pts}
                    </td>
                    <td className="py-3.5 px-6 text-slate-400 hidden sm:table-cell leading-relaxed">
                      {row.rationale}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="p-4 bg-slate-950/80 border-t border-slate-800 text-[11px] text-slate-400 flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono">
              Thresholds: <strong className="text-emerald-400">0–24 SAFE</strong> ·{' '}
              <strong className="text-amber-400">25–59 RISKY</strong> ·{' '}
              <strong className="text-rose-400">60–100 SCAM</strong>
            </span>
            <span className="text-slate-500">
              Rules calibrated for Indian & global student financial fraud patterns
            </span>
          </div>
        </div>
      </div>
    </section>
  );
};
