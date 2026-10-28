import React, { useState, useRef } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Trash2,
  ClipboardPaste,
  ExternalLink,
  ChevronRight,
  Info,
  CheckCircle2,
  Sparkles,
  Copy,
  Check,
} from 'lucide-react';
import { MESSAGE_SAMPLES } from '../data/samples';
import { MessageAnalysisResult, RiskLevel, WarningSign } from '../types/analyzer';
import { analyzeMessage } from '../utils/messageAnalyzer';
import { copyTextToClipboard, generateMessageAnalysisReport } from '../utils/clipboard';

interface MessageAnalyzerProps {
  onInspectExtractedUrl: (url: string) => void;
}

export const MessageAnalyzer: React.FC<MessageAnalyzerProps> = ({ onInspectExtractedUrl }) => {
  const [inputText, setInputText] = useState<string>('');
  const [result, setResult] = useState<MessageAnalysisResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [sampleLoadedNotice, setSampleLoadedNotice] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [copyError, setCopyError] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleSelectSample = (sampleId: string) => {
    const sample = MESSAGE_SAMPLES.find((s) => s.id === sampleId);
    if (sample) {
      // Per requirements: Loading a sample must NEVER automatically analyse it!
      setInputText(sample.text);
      setResult(null); // Clear previous analysis so visitor must click Analyse Message
      setErrorMessage(null);
      setCopyError(null);
      setCopiedReport(false);
      setSampleLoadedNotice(`Loaded sample: "${sample.title}". Click "Analyse Message" to evaluate.`);
      if (textareaRef.current) {
        textareaRef.current.focus();
      }
    }
  };

  const handleAnalyze = () => {
    setSampleLoadedNotice(null);
    setCopyError(null);
    setCopiedReport(false);
    if (!inputText.trim()) {
      setErrorMessage('Please enter or paste a message into the text area before analyzing.');
      setResult(null);
      if (textareaRef.current) {
        textareaRef.current.focus();
      }
      return;
    }
    setErrorMessage(null);
    try {
      const res = analyzeMessage(inputText);
      setResult(res);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Failed to analyze message content.');
      }
      setResult(null);
    }
  };

  const handleClear = () => {
    setInputText('');
    setResult(null);
    setErrorMessage(null);
    setCopyError(null);
    setCopiedReport(false);
    setSampleLoadedNotice(null);
    if (textareaRef.current) {
      textareaRef.current.focus();
    }
  };

  const handlePaste = async () => {
    setCopyError(null);
    setCopiedReport(false);
    try {
      const clipText = await navigator.clipboard.readText();
      if (clipText) {
        setInputText(clipText);
        setResult(null);
        setErrorMessage(null);
        setSampleLoadedNotice('Content pasted from clipboard. Click "Analyse Message" to evaluate.');
      }
    } catch {
      // Fallback if clipboard permission is denied
      if (textareaRef.current) {
        textareaRef.current.focus();
      }
    }
  };

  const handleCopyReport = async () => {
    if (!result) return;
    setCopyError(null);
    const summaryText = generateMessageAnalysisReport(result);
    const copyResult = await copyTextToClipboard(summaryText);
    if (copyResult.success) {
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2500);
    } else {
      setCopiedReport(false);
      setCopyError(copyResult.error || 'Failed to copy summary to clipboard.');
      setTimeout(() => setCopyError(null), 5000);
    }
  };

  const getVerdictStyles = (verdict: RiskLevel) => {
    switch (verdict) {
      case 'SAFE':
        return {
          bg: 'bg-emerald-950/40 border-emerald-500/30 text-emerald-400',
          badgeBg: 'bg-emerald-500 text-slate-950',
          barColor: 'bg-emerald-500',
          icon: ShieldCheck,
          label: 'SAFE',
        };
      case 'RISKY':
        return {
          bg: 'bg-amber-950/40 border-amber-500/30 text-amber-400',
          badgeBg: 'bg-amber-500 text-slate-950',
          barColor: 'bg-amber-500',
          icon: AlertTriangle,
          label: 'RISKY',
        };
      case 'SCAM':
        return {
          bg: 'bg-red-950/40 border-red-500/40 text-red-400',
          badgeBg: 'bg-red-500 text-white',
          barColor: 'bg-red-500',
          icon: ShieldAlert,
          label: 'SCAM',
        };
    }
  };

  const getSeverityBadge = (severity: 'low' | 'medium' | 'high' | 'critical') => {
    switch (severity) {
      case 'critical':
        return {
          label: 'Critical Severity',
          badge: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
          dot: 'bg-rose-400',
        };
      case 'high':
        return {
          label: 'High Severity',
          badge: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
          dot: 'bg-orange-400',
        };
      case 'medium':
        return {
          label: 'Medium Severity',
          badge: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
          dot: 'bg-amber-400',
        };
      case 'low':
      default:
        return {
          label: 'Low Severity',
          badge: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
          dot: 'bg-blue-400',
        };
    }
  };

  return (
    <section id="message-analyzer" className="py-16 lg:py-20 bg-[#0A1128] border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="max-w-3xl mb-8">
          <div className="text-xs font-semibold text-teal-400 tracking-wider uppercase mb-2">
            Module 01 · Heuristic Message Inspection
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight text-balance">
            Analyse Suspicious SMS, WhatsApp & Email Messages
          </h2>
          <p className="mt-2 text-sm sm:text-base text-slate-300">
            Paste any unsolicited communication. Our rule engine verifies against 8 high-frequency student fraud categories including fake internship fees, fake bank KYC threats, and fraudulent UPI refund requests.
          </p>
        </div>

        {/* Interactive Demo Examples Bar */}
        <div className="mb-6 p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between gap-4 mb-3">
            <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5 text-teal-400" />
              <span>Interactive Demonstration Samples</span>
            </span>
            <span className="text-xs text-slate-400 hidden sm:inline">
              Click a sample to load the text, then click "Analyse Message"
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {MESSAGE_SAMPLES.map((sample) => (
              <button
                key={sample.id}
                onClick={() => handleSelectSample(sample.id)}
                className="text-left p-3 rounded-lg bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer group flex flex-col justify-between"
              >
                <div>
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-teal-400 transition-colors">
                    {sample.title}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 line-clamp-2 leading-snug">
                    {sample.description}
                  </div>
                </div>
                <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
                  <span className="font-medium text-slate-300">{sample.type}</span>
                  <span className="text-teal-400 group-hover:translate-x-0.5 transition-transform">Load text →</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Notice after sample is loaded */}
        {sampleLoadedNotice && (
          <div className="mb-4 p-3 rounded-lg bg-teal-950/40 border border-teal-500/30 text-teal-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Info className="w-4 h-4 text-teal-400 shrink-0" />
              <span>{sampleLoadedNotice}</span>
            </div>
            <button
              onClick={() => setSampleLoadedNotice(null)}
              className="text-slate-400 hover:text-white text-xs underline cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Main Input Card */}
        <div className="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
          <div className="p-4 sm:p-5 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3 bg-slate-950/40">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
              <FileText className="w-4 h-4 text-teal-400" />
              <span>Message Raw Content</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handlePaste}
                className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-md transition-colors flex items-center gap-1.5 cursor-pointer"
                title="Paste from clipboard"
              >
                <ClipboardPaste className="w-3.5 h-3.5" />
                <span>Paste</span>
              </button>
              <button
                onClick={handleClear}
                className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-rose-400 bg-slate-800/60 hover:bg-slate-800 rounded-md transition-colors flex items-center gap-1.5 cursor-pointer"
                title="Clear text"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            </div>
          </div>

          <div className="p-4 sm:p-6">
            <textarea
              ref={textareaRef}
              value={inputText}
              onChange={(e) => {
                setInputText(e.target.value);
                if (errorMessage) setErrorMessage(null);
              }}
              onKeyDown={(e) => {
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                  e.preventDefault();
                  handleAnalyze();
                }
              }}
              aria-invalid={Boolean(errorMessage)}
              aria-describedby={errorMessage ? 'message-input-error' : undefined}
              rows={6}
              placeholder="Paste suspicious text message here (e.g., 'Dear customer, your bank account will be blocked... Please pay Rs 1,499 registration fee for internship...')"
              className={`w-full bg-[#070D18] text-slate-100 placeholder-slate-500 rounded-xl p-4 border text-sm font-sans leading-relaxed resize-y outline-none transition-all ${
                errorMessage
                  ? 'border-red-500/70 focus:border-red-500 focus:ring-1 focus:ring-red-500/40'
                  : 'border-slate-800 focus:border-teal-500 focus:ring-1 focus:ring-teal-500'
              }`}
            />

            {errorMessage && (
              <div
                id="message-input-error"
                role="alert"
                aria-live="polite"
                className="mt-3 p-3 rounded-lg bg-red-950/50 border border-red-800/50 text-red-300 text-xs flex items-center gap-2"
              >
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}

            <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="text-xs text-slate-400 flex items-center gap-4">
                <span>
                  Length:{' '}
                  <strong className="text-slate-200 font-mono tabular-nums">{inputText.length}</strong> chars
                </span>
                <span>·</span>
                <span>
                  Words:{' '}
                  <strong className="text-slate-200 font-mono tabular-nums">
                    {inputText.trim() ? inputText.trim().split(/\s+/).length : 0}
                  </strong>
                </span>
              </div>

              <button
                onClick={handleAnalyze}
                className="px-6 py-3 text-sm font-bold text-slate-950 bg-teal-400 hover:bg-teal-300 active:bg-teal-500 rounded-xl shadow-lg shadow-teal-500/20 transition-all flex items-center justify-center gap-2 cursor-pointer"
              >
                <ShieldCheck className="w-4 h-4" strokeWidth={2.5} />
                <span>Analyse Message</span>
              </button>
            </div>
          </div>
        </div>

        {/* Results Presentation Container */}
        {result && (
          <div className="mt-8 space-y-6">
            {/* 1. Verdict & Score Card */}
            {(() => {
              const styles = getVerdictStyles(result.verdict);
              const VerdictIcon = styles.icon;
              return (
                <div className={`p-6 sm:p-8 rounded-2xl border ${styles.bg} shadow-2xl`}>
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
                    {/* Left: Verdict Badge & Score Meter */}
                    <div className="lg:col-span-5 space-y-4">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <span className={`px-3.5 py-1 rounded-lg text-xs font-extrabold tracking-wider ${styles.badgeBg}`}>
                            {styles.label}
                          </span>
                          <span className="text-xs text-slate-400 font-mono">
                            {result.analysisTimestamp}
                          </span>
                        </div>
                        <div className="flex flex-col items-end">
                          <button
                            onClick={handleCopyReport}
                            className="px-2.5 py-1 text-xs font-medium bg-slate-900/90 hover:bg-slate-800 text-slate-200 border border-slate-700/80 rounded-md transition-all flex items-center gap-1.5 cursor-pointer shadow-xs"
                            title="Copy plain-text report to clipboard"
                          >
                            {copiedReport ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                                <span className="text-emerald-300 font-semibold">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5 text-teal-400" />
                                <span>Copy Summary</span>
                              </>
                            )}
                          </button>
                          {copyError && (
                            <span className="text-[11px] text-rose-400 font-medium mt-1 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                              {copyError}
                            </span>
                          )}
                        </div>
                      </div>

                      <div>
                        <div className="flex items-baseline justify-between mb-2">
                          <span className="text-sm font-semibold text-slate-300">Heuristic Risk Score</span>
                          <span className="text-3xl font-extrabold font-mono tracking-tight text-white tabular-nums">
                            {result.score} <span className="text-sm text-slate-400 font-normal">/ 100</span>
                          </span>
                        </div>

                        {/* Visual Progress Bar */}
                        <div className="w-full h-3 bg-slate-900/90 rounded-full overflow-hidden border border-slate-800">
                          <div
                            className={`h-full ${styles.barColor} transition-all duration-700 ease-out`}
                            style={{ width: `${result.score}%` }}
                          />
                        </div>

                        {/* Verdict Scale Markers */}
                        <div className="flex justify-between text-[11px] text-slate-400 mt-2 font-mono">
                          <span>0 Safe (0-24)</span>
                          <span>25 Risky (25-59)</span>
                          <span>60 Scam (60-100)</span>
                        </div>
                      </div>
                    </div>

                    {/* Right: Verdict Summary & Disclaimers */}
                    <div className="lg:col-span-7 lg:border-l lg:border-slate-800/80 lg:pl-8 space-y-3">
                      <div className="flex items-start gap-3">
                        <VerdictIcon className="w-6 h-6 shrink-0 mt-0.5" />
                        <div>
                          <h3 className="text-base font-bold text-white">Heuristic Evaluation Verdict</h3>
                          <p className="text-sm text-slate-300 mt-1 leading-relaxed">
                            {result.verdictSummary}
                          </p>
                        </div>
                      </div>

                      {/* Explicit Transparency Notice */}
                      <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-[12px] text-slate-400 leading-normal">
                        <strong className="text-slate-300">Heuristic Notice:</strong> These are preliminary demonstration rules, not validated fraud probabilities. A low score does not guarantee safety. Never disclose financial credentials to unsolicited contacts.
                      </div>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* 2. Explainable Detection Breakdown: "Why was this message flagged?" */}
            <div className="bg-slate-900 rounded-2xl border border-slate-800 p-6 sm:p-8 space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <span>Why was this message flagged?</span>
                    {result.warningSigns.length > 0 && (
                      <span className="text-xs font-mono px-2.5 py-0.5 rounded-full bg-slate-800 text-teal-300 border border-slate-700">
                        {result.warningSigns.length} {result.warningSigns.length === 1 ? 'indicator' : 'indicators'} detected
                      </span>
                    )}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Explainable breakdown of specific suspicious indicators detected by the rule engine.
                  </p>
                </div>

                {result.warningSigns.length > 0 && (
                  <div className="text-xs text-slate-400 font-mono self-start sm:self-auto bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 flex items-center gap-2">
                    <span>Score Contribution:</span>
                    <strong className="text-teal-400 font-bold">+{result.score} pts</strong>
                  </div>
                )}
              </div>

              {result.warningSigns.length === 0 ? (
                <div className="p-6 rounded-xl bg-slate-950/60 border border-slate-800 text-center space-y-3">
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                  <div className="text-sm font-semibold text-slate-200">
                    No significant warning indicators were detected by the current rules. This does not guarantee that the message is genuine.
                  </div>
                  <p className="text-xs text-slate-400 max-w-lg mx-auto leading-relaxed">
                    The rule engine evaluated this message against known patterns (including credential solicitations, account suspension threats, upfront internship/scholarship fees, and suspicious links) and found no matching indicators.
                  </p>
                  <div className="text-[11px] text-slate-500 pt-2 border-t border-slate-900">
                    Notice: A clean heuristic check does not establish verified authenticity. Routine announcements containing words like "bank", "payment", or "deadline" are not flagged unless paired with suspicious coercion or credential demands.
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Score Contribution Composition Bar */}
                  <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/90 space-y-2">
                    <div className="flex flex-wrap items-center justify-between text-xs gap-2">
                      <span className="text-slate-300 font-semibold flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-teal-400" />
                        Heuristic Score Composition:
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">
                        Evaluated independently (capped at 100)
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      {result.warningSigns.map((warning) => (
                        <div
                          key={warning.id}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs"
                        >
                          <span className="font-mono font-bold text-teal-400">+{warning.points}</span>
                          <span className="text-slate-300">{warning.category}</span>
                        </div>
                      ))}
                      <span className="text-xs font-mono text-slate-400 ml-auto pt-1 sm:pt-0">
                        = <strong className="text-white font-bold">{result.score}</strong> / 100 ({result.verdict})
                      </span>
                    </div>
                  </div>

                  {/* Indicator Cards */}
                  <div className="space-y-4 pt-1">
                    {result.warningSigns.map((warning, index) => {
                      const severityStyle = getSeverityBadge(warning.severity);
                      return (
                        <div
                          key={warning.id}
                          className="p-5 rounded-xl bg-slate-950/70 border border-slate-800/90 space-y-3 transition-all hover:border-slate-700/80"
                        >
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div className="space-y-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="text-xs font-mono text-slate-400 font-bold">
                                  #{String(index + 1).padStart(2, '0')}
                                </span>
                                <span className="text-sm font-bold text-white">
                                  {warning.title}
                                </span>
                                <span
                                  className={`text-[11px] font-semibold px-2 py-0.5 rounded-md border flex items-center gap-1.5 ${severityStyle.badge}`}
                                >
                                  <span className={`w-1.5 h-1.5 rounded-full ${severityStyle.dot}`} />
                                  <span>{severityStyle.label}</span>
                                </span>
                              </div>
                              <div className="text-xs text-slate-400 font-medium">
                                Category: <span className="text-slate-300">{warning.category}</span>
                              </div>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              <span className="text-xs font-bold font-mono px-2.5 py-1 rounded-lg bg-teal-950/60 text-teal-400 border border-teal-800/60">
                                +{warning.points} pts
                              </span>
                            </div>
                          </div>

                          {/* Matched Evidence Snippets */}
                          {warning.matchedSnippets.length > 0 && (
                            <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800/80 space-y-1.5">
                              <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
                                Matched Phrase Evidence:
                              </span>
                              <div className="flex flex-wrap gap-1.5">
                                {warning.matchedSnippets.map((snippet, i) => (
                                  <code
                                    key={i}
                                    className="px-2.5 py-1 rounded bg-slate-950 border border-amber-500/30 text-amber-300 font-mono text-xs break-all"
                                  >
                                    "{snippet}"
                                  </code>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Explanation */}
                          <div className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                            <strong className="text-slate-200">Why this is suspicious: </strong>
                            <span>{warning.explanation}</span>
                          </div>

                          {/* Recommended Student Action */}
                          <div className="pt-2 border-t border-slate-900 text-xs text-slate-400 flex items-start gap-2">
                            <strong className="text-teal-400 shrink-0">Guidance:</strong>
                            <span className="text-slate-300">{warning.recommendation}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* 3. Extracted URLs Section */}
            {result.extractedUrls.length > 0 && (
              <div className="bg-slate-900 rounded-2xl border border-slate-800 p-6 sm:p-8 space-y-4">
                <div>
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <span>Extracted Web Links in Message</span>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-teal-950 text-teal-400 border border-teal-800">
                      {result.extractedUrls.length} found
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    These URLs were embedded within the text. You can test each link in our safe, offline URL inspector without opening it.
                  </p>
                </div>

                <div className="space-y-3">
                  {result.extractedUrls.map((url, i) => (
                    <div
                      key={i}
                      className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                    >
                      <div className="flex items-center gap-2 overflow-hidden">
                        <ExternalLink className="w-4 h-4 text-teal-400 shrink-0" />
                        <span className="font-mono text-xs text-slate-200 truncate select-all">{url}</span>
                      </div>

                      <button
                        onClick={() => onInspectExtractedUrl(url)}
                        className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-teal-400 hover:bg-teal-300 rounded-lg transition-colors flex items-center gap-1.5 shrink-0 cursor-pointer self-start sm:self-auto"
                      >
                        <span>Inspect in URL Analyser</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 4. Practical Student Safety Recommendations */}
            <div className="bg-slate-900 rounded-2xl border border-slate-800 p-6 sm:p-8 space-y-4">
              <h3 className="text-lg font-bold text-white">Recommended Safety Actions</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {result.recommendations.map((rec, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 text-xs sm:text-sm text-slate-300 flex items-start gap-2.5"
                  >
                    <CheckCircle2 className="w-4 h-4 text-teal-400 shrink-0 mt-0.5" />
                    <span className="leading-relaxed">{rec}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
