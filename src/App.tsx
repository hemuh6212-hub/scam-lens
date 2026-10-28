/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Header } from './components/Header';
import { Hero } from './components/Hero';
import { MessageAnalyzer } from './components/MessageAnalyzer';
import { UrlAnalyzer } from './components/UrlAnalyzer';
import { HowItWorks } from './components/HowItWorks';
import { SafetyTips } from './components/SafetyTips';
import { Footer } from './components/Footer';

export default function App() {
  const [selectedUrlForInspection, setSelectedUrlForInspection] = useState<string>('');

  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleInspectExtractedUrl = (url: string) => {
    setSelectedUrlForInspection(url);
    scrollToSection('url-analyzer');
  };

  return (
    <div className="min-h-screen bg-[#070D18] text-slate-100 flex flex-col font-sans selection:bg-teal-500 selection:text-slate-950">
      {/* Top Navigation */}
      <Header
        onNavigateToMessage={() => scrollToSection('message-analyzer')}
        onNavigateToUrl={() => scrollToSection('url-analyzer')}
      />

      {/* Main Content Body */}
      <main className="flex-1">
        {/* Hero Section */}
        <Hero
          onScanMessageClick={() => scrollToSection('message-analyzer')}
          onInspectUrlClick={() => scrollToSection('url-analyzer')}
        />

        {/* Message Analysis Section */}
        <MessageAnalyzer onInspectExtractedUrl={handleInspectExtractedUrl} />

        {/* URL Analysis Section */}
        <UrlAnalyzer initialUrl={selectedUrlForInspection} />

        {/* How It Works & Transparency */}
        <HowItWorks />

        {/* Student Safety Rules & Emergency Helplines */}
        <SafetyTips />
      </main>

      {/* Footer & Disclaimer */}
      <Footer />
    </div>
  );
}
