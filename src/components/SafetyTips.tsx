import React from 'react';
import { ShieldCheck, AlertOctagon, HelpCircle, PhoneCall, Smartphone, Briefcase, CreditCard } from 'lucide-react';

export const SafetyTips: React.FC = () => {
  const tips = [
    {
      icon: CreditCard,
      title: 'The Golden Rule of UPI PINs',
      summary: 'Entering your UPI PIN ALWAYS transfers money OUT of your bank account.',
      details:
        'Scammers send "Collect Requests" or spoof QR codes claiming you must enter your PIN to "receive a refund" or "claim a prize". You never need to enter your PIN or password to receive funds.',
    },
    {
      icon: Briefcase,
      title: 'Internship & Job Onboarding Red Flags',
      summary: 'Legitimate employers pay you for work—they never ask you to pay them.',
      details:
        'Any job offer demanding an upfront "security deposit", "laptop courier fee", "ID card registration", or "documentation fee" is 100% fraudulent. Genuine recruiters never conduct recruitment over anonymous Telegram channels.',
    },
    {
      icon: Smartphone,
      title: 'Never Install Sideloaded APK Files',
      summary: 'Scammers distribute malicious .apk files to intercept SMS verification codes.',
      details:
        'Fraudsters often send links masquerading as "Bank Update App", "Electricity Bill App", or "Student Grant Portal". Installing these apps grants permissions to read all incoming OTPs and remotely compromise your phone.',
    },
    {
      icon: AlertOctagon,
      title: 'Ignore Fake "Account Blocked" Deadlines',
      summary: 'Artificial panic is a psychological trick designed to bypass your rational thinking.',
      details:
        'Threats like "Your SIM will be deactivated in 2 hours" or "Your bank account is frozen due to missing KYC" are fabricated. Banks and network operators never mandate verification through third-party URL links.',
    },
  ];

  return (
    <section id="safety-tips" className="py-16 lg:py-24 bg-[#070D18] border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl mb-12">
          <div className="text-xs font-semibold text-teal-400 tracking-wider uppercase mb-2">
            Student Defense Playbook
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight text-balance">
            Essential Cyber Safety Rules Every Student Should Know
          </h2>
          <p className="mt-2 text-sm sm:text-base text-slate-300">
            Fraudsters specifically target college students who are seeking internships, managing tight budgets, and adopting digital UPI payments. Keep these four cardinal rules top of mind.
          </p>
        </div>

        {/* 4 Cards Bento Layout */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-12">
          {tips.map((tip, idx) => {
            const Icon = tip.icon;
            return (
              <div
                key={idx}
                className="p-6 sm:p-8 rounded-2xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-colors space-y-4"
              >
                <div className="w-10 h-10 rounded-xl bg-teal-950/80 border border-teal-500/30 flex items-center justify-center text-teal-400">
                  <Icon className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base sm:text-lg font-bold text-white">{tip.title}</h3>
                  <p className="text-xs sm:text-sm font-semibold text-teal-300 mt-1">{tip.summary}</p>
                </div>
                <p className="text-xs sm:text-sm text-slate-400 leading-relaxed pt-2 border-t border-slate-800/80">
                  {tip.details}
                </p>
              </div>
            );
          })}
        </div>

        {/* Emergency Helplines Callout Box */}
        <div className="p-6 sm:p-8 rounded-2xl bg-gradient-to-br from-slate-900 to-[#0B132B] border border-teal-500/30 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-teal-400 text-xs font-bold uppercase tracking-wider">
              <PhoneCall className="w-4 h-4" />
              <span>Cyber Fraud Incident Response</span>
            </div>
            <h4 className="text-base sm:text-lg font-bold text-white">
              Already shared sensitive details or lost funds?
            </h4>
            <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
              In India, call the <strong>National Cyber Crime Helpline at 1930</strong> immediately to freeze fraudulent bank transactions, or register an official incident on <strong>cybercrime.gov.in</strong>. Notify your bank to block your cards and UPI handles right away.
            </p>
          </div>

          <div className="shrink-0 flex flex-col sm:flex-row gap-3">
            <a
              href="tel:1930"
              className="px-5 py-3 rounded-xl bg-teal-400 hover:bg-teal-300 text-slate-950 font-bold text-xs sm:text-sm transition-colors text-center shadow-lg shadow-teal-500/20"
            >
              Dial 1930 Helpline
            </a>
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              className="px-5 py-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-medium text-xs sm:text-sm border border-slate-700 transition-colors text-center"
            >
              cybercrime.gov.in
            </a>
          </div>
        </div>
      </div>
    </section>
  );
};
