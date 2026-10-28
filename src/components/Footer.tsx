import React from 'react';
import { ShieldCheck, Heart, Lock } from 'lucide-react';

export const Footer: React.FC = () => {
  const scrollTo = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <footer className="bg-[#050912] text-slate-400 text-xs border-t border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 lg:py-16">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-8 mb-12">
          {/* Brand Col */}
          <div className="md:col-span-5 space-y-4">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-teal-400 flex items-center justify-center text-slate-950 font-bold">
                <ShieldCheck className="w-4 h-4" strokeWidth={2.5} />
              </div>
              <span className="text-white text-lg font-extrabold tracking-tight">ScamLens</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed max-w-sm">
              Heuristic cybersecurity website helping students spot fraudulent messages, fake internship fees, and suspicious links before losing money or credentials.
            </p>
            <div className="flex items-center gap-2 text-[11px] text-teal-400">
              <Lock className="w-3.5 h-3.5" />
              <span>Zero-Data Retention · 100% Client-Side Evaluation</span>
            </div>
          </div>

          {/* Nav links */}
          <div className="md:col-span-3 space-y-3">
            <div className="text-white text-xs font-semibold uppercase tracking-wider">Navigation</div>
            <ul className="space-y-2">
              <li>
                <button
                  onClick={() => scrollTo('message-analyzer')}
                  className="hover:text-teal-400 transition-colors text-left"
                >
                  Message Scanner
                </button>
              </li>
              <li>
                <button
                  onClick={() => scrollTo('url-analyzer')}
                  className="hover:text-teal-400 transition-colors text-left"
                >
                  URL Inspector
                </button>
              </li>
              <li>
                <button
                  onClick={() => scrollTo('how-it-works')}
                  className="hover:text-teal-400 transition-colors text-left"
                >
                  How It Works
                </button>
              </li>
              <li>
                <button
                  onClick={() => scrollTo('safety-tips')}
                  className="hover:text-teal-400 transition-colors text-left"
                >
                  Student Safety Tips
                </button>
              </li>
            </ul>
          </div>

          {/* Educational Scope */}
          <div className="md:col-span-4 space-y-3">
            <div className="text-white text-xs font-semibold uppercase tracking-wider">Notice for Students</div>
            <p className="text-[12px] text-slate-400 leading-relaxed">
              Always independently verify unexpected communications by contacting official college faculty, hostel administration, or certified bank branches directly.
            </p>
            <div className="text-[11px] text-slate-500 font-mono">
              Designed for College Hackathon Presentation
            </div>
          </div>
        </div>

        {/* Mandatory Legal & Heuristic Disclaimer */}
        <div className="pt-8 border-t border-slate-800/80 space-y-3">
          <p className="text-[11px] text-slate-400 leading-relaxed text-center sm:text-left">
            <strong>Disclaimer:</strong> ScamLens provides preliminary heuristic evaluations based on deterministic syntactic and behavioral rules. It does not replace certified threat intelligence feeds, official bank fraud monitoring, or law enforcement investigation. A low score does not guarantee safety, and a high score indicates potential risk rather than a definitive legal conclusion. ScamLens does not save, store, or transmit submitted message texts or URLs to external third parties.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] text-slate-400 pt-2">
            <div>
              &copy; {new Date().getFullYear()} ScamLens. Built for Student Cyber Awareness.
            </div>
            <div className="flex items-center gap-1">
              <span>Browser-based heuristic engine</span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};
