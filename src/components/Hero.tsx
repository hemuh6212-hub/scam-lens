import React from 'react';
import { ShieldCheck, Search, Link2, Lock, ArrowDown } from 'lucide-react';
import heroShieldImage from '../assets/images/scamlens_hero_shield_1792910679625.jpg';

interface HeroProps {
  onScanMessageClick: () => void;
  onInspectUrlClick: () => void;
}

export const Hero: React.FC<HeroProps> = ({ onScanMessageClick, onInspectUrlClick }) => {
  return (
    <section className="relative overflow-hidden pt-12 pb-16 lg:pt-16 lg:pb-24 border-b border-slate-800/80">
      {/* Background ambient lighting */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[350px] bg-teal-500/10 blur-[130px] rounded-full pointer-events-none" />
      <div className="absolute top-1/3 right-10 w-[350px] h-[250px] bg-amber-500/5 blur-[120px] rounded-full pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center">
          {/* Left Column: Hero Narrative */}
          <div className="lg:col-span-7 space-y-6">
            <div className="flex items-center gap-2 text-xs font-semibold text-teal-400 tracking-wider uppercase">
              <span className="w-2 h-2 rounded-sm bg-teal-400 inline-block" />
              <span>Student Cyber Defence System</span>
              <span className="text-slate-500">·</span>
              <span className="text-slate-400 normal-case">Zero-telemetry local inspection</span>
            </div>

            <h1 className="text-4xl sm:text-5xl lg:text-[3.25rem] font-extrabold text-white tracking-tight leading-[1.15] text-balance">
              Identify Fraudulent Messages & Suspicious Links Before You Pay.
            </h1>

            <p className="text-base sm:text-lg text-slate-300 leading-relaxed max-w-2xl">
              College students are routinely targeted by fake internship kit fees, deceptive UPI refund traps, and phishing SMS alerts. ScamLens dissects suspicious communications in real time using transparent, explainable heuristic cybersecurity rules—completely offline in your browser.
            </p>

            <div className="pt-2 flex flex-wrap items-center gap-4">
              <button
                onClick={onScanMessageClick}
                className="px-6 py-3.5 text-sm font-bold text-slate-950 bg-teal-400 hover:bg-teal-300 active:bg-teal-500 rounded-xl transition-all shadow-lg shadow-teal-500/25 flex items-center gap-2 cursor-pointer whitespace-nowrap"
              >
                <Search className="w-4 h-4" strokeWidth={2.5} />
                <span>Analyse a Message</span>
              </button>

              <button
                onClick={onInspectUrlClick}
                className="px-6 py-3.5 text-sm font-semibold text-slate-200 bg-slate-900/80 hover:bg-slate-800 border border-slate-700/80 rounded-xl transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap"
              >
                <Link2 className="w-4 h-4 text-teal-400" />
                <span>Inspect Suspicious Link</span>
              </button>
            </div>

            {/* Privacy Promise Notice */}
            <div className="pt-4 flex items-center gap-2 text-xs text-slate-400">
              <Lock className="w-3.5 h-3.5 text-teal-400 shrink-0" />
              <span>
                <strong>100% Client-Side Privacy:</strong> Your text and links are evaluated locally in memory. Zero data is logged or transmitted to external servers.
              </span>
            </div>
          </div>

          {/* Right Column: Hero Visual Asset */}
          <div className="lg:col-span-5 relative">
            <div className="relative rounded-2xl overflow-hidden border border-slate-700/70 shadow-2xl shadow-teal-950/40 bg-slate-900 aspect-[16/9] lg:aspect-auto lg:h-[380px]">
              <img
                src={heroShieldImage}
                alt="ScamLens cybersecurity neural lens analyzing suspicious message patterns"
                className="w-full h-full object-cover object-center"
                referrerPolicy="no-referrer"
                onError={(e) => {
                  // Fallback container if image cannot load
                  (e.target as HTMLElement).style.display = 'none';
                }}
              />
              {/* Subtle gradient overlay to tie into navy theme */}
              <div className="absolute inset-0 bg-gradient-to-t from-[#070D18]/80 via-transparent to-transparent pointer-events-none" />

              <div className="absolute bottom-4 left-4 right-4 bg-slate-950/80 backdrop-blur-md border border-slate-800 rounded-lg p-3 text-xs text-slate-300 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-teal-400" />
                  <span className="font-semibold text-white">Heuristic Guard Active</span>
                </div>
                <span className="text-slate-400 font-mono text-[11px]">8 Rule Categories</span>
              </div>
            </div>
          </div>
        </div>

        {/* 4-Column KPI Trust Strip */}
        <div className="mt-14 pt-10 border-t border-slate-800/80 grid grid-cols-2 md:grid-cols-4 gap-6">
          <div className="space-y-1">
            <div className="text-2xl font-bold font-mono text-white tabular-nums">8 Rules</div>
            <div className="text-xs text-slate-400">Threat patterns analyzed concurrently</div>
          </div>
          <div className="space-y-1">
            <div className="text-2xl font-bold font-mono text-teal-400 tabular-nums">0 Byt</div>
            <div className="text-xs text-slate-400">Transmitted externally. Pure client-side code.</div>
          </div>
          <div className="space-y-1">
            <div className="text-2xl font-bold font-mono text-amber-400 tabular-nums">0–100</div>
            <div className="text-xs text-slate-400">Transparent heuristic scoring scale</div>
          </div>
          <div className="space-y-1">
            <div className="text-2xl font-bold font-mono text-cyan-400 tabular-nums">&lt; 15 ms</div>
            <div className="text-xs text-slate-400">Deterministic local analysis speed</div>
          </div>
        </div>
      </div>
    </section>
  );
};
