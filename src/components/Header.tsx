import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, Menu, X, ArrowUpRight } from 'lucide-react';

interface HeaderProps {
  onNavigateToMessage: () => void;
  onNavigateToUrl: () => void;
}

export const Header: React.FC<HeaderProps> = ({ onNavigateToMessage, onNavigateToUrl }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const scrollToSection = (id: string) => {
    setMobileMenuOpen(false);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <header className="sticky top-0 z-50 bg-[#070D18]/90 backdrop-blur-md border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between gap-8 h-16">
          {/* Zone 1: Single text element wordmark */}
          <a
            href="#"
            className="flex items-center gap-2.5 text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0 group"
          >
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-teal-400 to-cyan-600 flex items-center justify-center text-slate-950 shadow-sm shadow-teal-500/20 group-hover:scale-105 transition-transform duration-200">
              <ShieldCheck className="w-5 h-5" strokeWidth={2.5} />
            </div>
            <div className="flex items-baseline">
              <span className="text-white text-xl font-extrabold tracking-tight">Scam</span>
              <span className="text-teal-400 text-xl font-extrabold tracking-tight">Lens</span>
            </div>
          </a>

          {/* Zone 2: 4 clean single-line navigation links */}
          <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-slate-300">
            <button
              onClick={() => scrollToSection('message-analyzer')}
              className="hover:text-teal-400 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Message Scanner
            </button>
            <button
              onClick={() => scrollToSection('url-analyzer')}
              className="hover:text-teal-400 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              URL Inspector
            </button>
            <button
              onClick={() => scrollToSection('how-it-works')}
              className="hover:text-teal-400 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              How It Works
            </button>
            <button
              onClick={() => scrollToSection('safety-tips')}
              className="hover:text-teal-400 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Student Safety
            </button>
          </nav>

          {/* Zone 3: 1 primary action */}
          <div className="hidden md:flex items-center gap-3 shrink-0">
            <button
              onClick={onNavigateToMessage}
              className="px-4 py-2 text-xs font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 active:bg-teal-500 rounded-lg transition-colors whitespace-nowrap shrink-0 shadow-sm shadow-teal-500/20 cursor-pointer flex items-center gap-1.5"
            >
              <span>Scan Message Now</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Mobile hamburger button */}
          <div className="flex md:hidden items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 focus:outline-none cursor-pointer"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile menu dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-slate-800 bg-[#0B132B] px-4 pt-3 pb-5 space-y-2">
          <button
            onClick={() => scrollToSection('message-analyzer')}
            className="block w-full text-left py-2 px-3 text-base font-medium text-slate-200 hover:bg-slate-800 rounded-md"
          >
            Message Scanner
          </button>
          <button
            onClick={() => scrollToSection('url-analyzer')}
            className="block w-full text-left py-2 px-3 text-base font-medium text-slate-200 hover:bg-slate-800 rounded-md"
          >
            URL Inspector
          </button>
          <button
            onClick={() => scrollToSection('how-it-works')}
            className="block w-full text-left py-2 px-3 text-base font-medium text-slate-200 hover:bg-slate-800 rounded-md"
          >
            How It Works
          </button>
          <button
            onClick={() => scrollToSection('safety-tips')}
            className="block w-full text-left py-2 px-3 text-base font-medium text-slate-200 hover:bg-slate-800 rounded-md"
          >
            Student Safety
          </button>
          <div className="pt-2">
            <button
              onClick={() => {
                setMobileMenuOpen(false);
                onNavigateToMessage();
              }}
              className="w-full py-2.5 text-center text-sm font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-lg shadow-sm"
            >
              Scan Message Now
            </button>
          </div>
        </div>
      )}
    </header>
  );
};
