import React, { useState, useEffect, useRef } from 'react';
import {
  Link2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Trash2,
  Info,
  CheckCircle2,
  Server,
  Globe,
  FileCode,
  Lock,
  Unlock,
  Copy,
  Check,
  Activity,
  ArrowRight,
  ExternalLink,
  RefreshCw,
  Layers,
  Radio,
} from 'lucide-react';
import { URL_SAMPLES } from '../data/samples';
import { UrlAnalysisResult, UrlRiskLevel, SandboxScanResult } from '../types/analyzer';
import { analyzeUrl } from '../utils/urlAnalyzer';
import { copyTextToClipboard, generateUrlStructuralReport, generateSandboxScanReport } from '../utils/clipboard';

interface UrlAnalyzerProps {
  initialUrl?: string;
}

export const UrlAnalyzer: React.FC<UrlAnalyzerProps> = ({ initialUrl }) => {
  const [urlInput, setUrlInput] = useState<string>('');
  const [result, setResult] = useState<UrlAnalysisResult | null>(null);
  const [sandboxResult, setSandboxResult] = useState<SandboxScanResult | null>(null);
  const [isSandboxScanning, setIsSandboxScanning] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [sandboxError, setSandboxError] = useState<string | null>(null);
  const [sampleLoadedNotice, setSampleLoadedNotice] = useState<string | null>(null);
  const [copiedReport, setCopiedReport] = useState<boolean>(false);
  const [copiedSandboxReport, setCopiedSandboxReport] = useState<boolean>(false);
  const [copyError, setCopyError] = useState<string | null>(null);
  const [sandboxCopyError, setSandboxCopyError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // When initialUrl is passed from MessageAnalyzer, populate it
  useEffect(() => {
    if (initialUrl) {
      setUrlInput(initialUrl);
      setResult(null);
      setSandboxResult(null);
      setErrorMessage(null);
      setSandboxError(null);
      setCopyError(null);
      setSandboxCopyError(null);
      setCopiedReport(false);
      setCopiedSandboxReport(false);
      setSampleLoadedNotice(`Transferred URL from message. Choose "Inspect Syntax" or "Live Sandbox Scan".`);
      if (inputRef.current) {
        inputRef.current.focus();
      }
    }
  }, [initialUrl]);

  const handleSelectSample = (sampleUrl: string) => {
    setUrlInput(sampleUrl);
    setResult(null);
    setSandboxResult(null);
    setErrorMessage(null);
    setSandboxError(null);
    setCopyError(null);
    setSandboxCopyError(null);
    setCopiedReport(false);
    setCopiedSandboxReport(false);
    setSampleLoadedNotice(`Loaded sample URL. Choose "Inspect Syntax" or "Live Sandbox Scan" to evaluate.`);
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  // 1. Fast local structural inspection (100% offline)
  const handleInspect = () => {
    setSampleLoadedNotice(null);
    setSandboxError(null);
    setCopyError(null);
    setSandboxCopyError(null);
    setCopiedReport(false);
    setCopiedSandboxReport(false);
    if (!urlInput.trim()) {
      setErrorMessage('Please enter or paste a URL to inspect.');
      setResult(null);
      return;
    }
    setErrorMessage(null);
    try {
      const res = analyzeUrl(urlInput);
      setResult(res);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Failed to analyze the specified URL.');
      }
      setResult(null);
    }
  };

  // 2. Deep Live Sandbox Scan (backend proxy connection, DOM parsing, form & content inspection)
  const handleSandboxScan = async () => {
    setSampleLoadedNotice(null);
    setSandboxError(null);
    setErrorMessage(null);
    setCopyError(null);
    setSandboxCopyError(null);
    setCopiedReport(false);
    setCopiedSandboxReport(false);

    const trimmed = urlInput.trim();
    if (!trimmed) {
      setErrorMessage('Please enter or paste a URL to scan in sandbox.');
      return;
    }

    // Always run local structural analysis first for immediate baseline
    try {
      const res = analyzeUrl(trimmed);
      setResult(res);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setErrorMessage(err.message);
        return;
      }
    }

    setIsSandboxScanning(true);
    setSandboxResult(null);

    try {
      const resp = await fetch('/api/sandbox-scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: trimmed }),
      });

      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data.error || `Server responded with status ${resp.status}`);
      }
      setSandboxResult(data as SandboxScanResult);
    } catch (err: unknown) {
      setSandboxError(err instanceof Error ? err.message : 'Sandbox connection failed.');
    } finally {
      setIsSandboxScanning(false);
    }
  };

  const handleClear = () => {
    setUrlInput('');
    setResult(null);
    setSandboxResult(null);
    setErrorMessage(null);
    setSandboxError(null);
    setCopyError(null);
    setSandboxCopyError(null);
    setCopiedReport(false);
    setCopiedSandboxReport(false);
    setSampleLoadedNotice(null);
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  const handlePaste = async () => {
    setCopyError(null);
    setSandboxCopyError(null);
    setCopiedReport(false);
    setCopiedSandboxReport(false);
    try {
      const clipText = await navigator.clipboard.readText();
      if (clipText) {
        setUrlInput(clipText.trim());
        setResult(null);
        setSandboxResult(null);
        setErrorMessage(null);
        setSandboxError(null);
        setSampleLoadedNotice('Pasted link from clipboard. Choose inspection mode below.');
      }
    } catch {
      if (inputRef.current) {
        inputRef.current.focus();
      }
    }
  };

  const handleCopyReport = async () => {
    if (!result) return;
    setCopyError(null);
    const summaryText = generateUrlStructuralReport(result);
    const copyResult = await copyTextToClipboard(summaryText);
    if (copyResult.success) {
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2500);
    } else {
      setCopiedReport(false);
      setCopyError(copyResult.error || 'Failed to copy syntax report to clipboard.');
      setTimeout(() => setCopyError(null), 5000);
    }
  };

  const handleCopySandboxReport = async () => {
    if (!sandboxResult) return;
    setSandboxCopyError(null);
    const reportText = generateSandboxScanReport(sandboxResult);
    const copyResult = await copyTextToClipboard(reportText);
    if (copyResult.success) {
      setCopiedSandboxReport(true);
      setTimeout(() => setCopiedSandboxReport(false), 2500);
    } else {
      setCopiedSandboxReport(false);
      setSandboxCopyError(copyResult.error || 'Failed to copy sandbox report to clipboard.');
      setTimeout(() => setSandboxCopyError(null), 5000);
    }
  };

  const getVerdictStyles = (verdict: UrlRiskLevel) => {
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
          label: 'RISKY PATTERNS DETECTED',
        };
      case 'SUSPICIOUS':
        return {
          bg: 'bg-red-950/40 border-red-500/40 text-red-400',
          badgeBg: 'bg-red-500 text-white',
          barColor: 'bg-red-500',
          icon: ShieldAlert,
          label: 'HIGH-RISK / SUSPICIOUS',
        };
    }
  };

  return (
    <section id="url-analyzer" className="py-16 lg:py-20 bg-[#070D18] border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="max-w-3xl mb-8">
          <div className="text-xs font-semibold text-teal-400 tracking-wider uppercase mb-2 flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-teal-400 animate-pulse" />
            <span>Module 02 · URL Structural Inspector & Live Sandbox</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight text-balance">
            Inspect Syntax & Scan Complete Live Websites in Sandbox
          </h2>
          <p className="mt-2 text-sm sm:text-base text-slate-300">
            Never risk clicking a link directly. ScamLens checks URL syntax offline in browser memory, and connects in an isolated backend sandbox to audit DOM forms, password harvesting, redirect chains, and on-page scam language.
          </p>
        </div>

        {/* Demo Samples Selector */}
        <div className="mb-6 p-4 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm">
          <div className="flex items-center justify-between gap-4 mb-3">
            <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-teal-400" />
              <span>Sample URLs to Test</span>
            </span>
            <span className="text-xs text-slate-400 hidden sm:inline">
              Select a sample, then choose an inspection mode below
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {URL_SAMPLES.map((sample) => (
              <button
                key={sample.id}
                onClick={() => handleSelectSample(sample.url)}
                className="text-left p-3 rounded-lg bg-slate-950/70 hover:bg-slate-800/80 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer group flex flex-col justify-between"
              >
                <div>
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-teal-400 transition-colors">
                    {sample.label}
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 mt-1 truncate">
                    {sample.url}
                  </div>
                </div>
                <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
                  <span className="text-slate-400">{sample.category}</span>
                  <span className="text-teal-400 group-hover:translate-x-0.5 transition-transform">Load →</span>
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

        {/* Input Card */}
        <div className="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl p-4 sm:p-6">
          <label htmlFor="url-input-field" className="block text-xs font-semibold text-slate-300 mb-2">
            Paste Target Link or Domain
          </label>
          <div className="space-y-3">
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <Link2 className="w-4 h-4" />
              </div>
              <input
                id="url-input-field"
                ref={inputRef}
                type="text"
                value={urlInput}
                onChange={(e) => {
                  setUrlInput(e.target.value);
                  if (errorMessage) setErrorMessage(null);
                  if (sandboxError) setSandboxError(null);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    handleSandboxScan();
                  }
                }}
                placeholder="e.g., http://hdfcbank-verify-kyc.xyz/login.php or bit.ly/student-bonus"
                className="w-full bg-[#070D18] text-slate-100 placeholder-slate-500 rounded-xl pl-10 pr-24 py-3.5 border border-slate-800 focus:border-teal-500 focus:ring-1 focus:ring-teal-500 text-sm font-mono outline-none transition-all"
              />
              <div className="absolute inset-y-0 right-0 pr-2 flex items-center gap-1">
                <button
                  onClick={handlePaste}
                  className="px-2 py-1 text-[11px] font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors"
                  title="Paste from clipboard"
                >
                  Paste
                </button>
                {urlInput && (
                  <button
                    onClick={handleClear}
                    className="p-1 text-slate-400 hover:text-rose-400 rounded transition-colors"
                    title="Clear input"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>

            {/* Action Buttons: Fast Structural Check vs Live Sandbox Scan */}
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-1">
              <div className="text-xs text-slate-400 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-teal-400 shrink-0" />
                <span>Sandbox connects safely in isolated backend. User IP is never exposed.</span>
              </div>

              <div className="flex items-center gap-2.5">
                <button
                  onClick={handleInspect}
                  disabled={isSandboxScanning}
                  className="flex-1 sm:flex-none px-4 py-3 text-xs sm:text-sm font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 active:bg-slate-900 border border-slate-700 rounded-xl transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                  title="Inspect URL structure offline without connecting"
                >
                  <FileCode className="w-4 h-4 text-teal-400" />
                  <span>Inspect Syntax</span>
                </button>

                <button
                  onClick={handleSandboxScan}
                  disabled={isSandboxScanning}
                  className="flex-1 sm:flex-none px-5 py-3 text-xs sm:text-sm font-bold text-slate-950 bg-teal-400 hover:bg-teal-300 active:bg-teal-500 rounded-xl transition-all shadow-lg shadow-teal-500/20 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-75 whitespace-nowrap"
                  title="Connect in backend sandbox to audit forms, passwords, redirects, and page text"
                >
                  {isSandboxScanning ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Scanning in Sandbox...</span>
                    </>
                  ) : (
                    <>
                      <Activity className="w-4 h-4" strokeWidth={2.5} />
                      <span>Live Sandbox Scan</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {errorMessage && (
            <div className="mt-3 p-3 rounded-lg bg-red-950/50 border border-red-800/50 text-red-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {sandboxError && (
            <div className="mt-3 p-3 rounded-lg bg-amber-950/40 border border-amber-800/40 text-amber-300 text-xs flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold">Live Sandbox Notice: </span>
                <span>{sandboxError}</span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  The target site could not be retrieved (often indicates a taken-down phishing host, invalid domain, or SSRF block). Showing structural syntax analysis below.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Loading Sandbox State */}
        {isSandboxScanning && (
          <div className="mt-8 p-6 rounded-2xl bg-slate-900 border border-teal-500/30 text-center space-y-3 shadow-xl">
            <RefreshCw className="w-8 h-8 text-teal-400 animate-spin mx-auto" />
            <h3 className="text-base font-bold text-white">Connecting in Isolated Backend Sandbox</h3>
            <p className="text-xs text-slate-400 max-w-lg mx-auto leading-relaxed">
              Fetching target page safely with anti-SSRF protection. Tracing redirect hops, inspecting DOM forms, checking for credential harvesting inputs, and analyzing visible on-page content...
            </p>
          </div>
        )}

        {/* ========================================================================= */}
        {/* LIVE SANDBOX DEEP SCAN REPORT CARD (When available)                       */}
        {/* ========================================================================= */}
        {sandboxResult && !isSandboxScanning && (
          <div className="mt-8 space-y-6">
            <div className="bg-slate-900 rounded-2xl border border-teal-500/40 p-6 sm:p-8 shadow-2xl relative overflow-hidden">
              <div className="absolute top-0 right-0 px-4 py-1.5 bg-teal-500 text-slate-950 text-[11px] font-extrabold uppercase tracking-wider rounded-bl-xl flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5" />
                <span>Live Sandbox Scan Completed</span>
              </div>

              {/* Sandbox Top Summary */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
                <div>
                  <div className="text-xs font-mono text-teal-400 uppercase tracking-wider mb-1 flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5" />
                    <span>Target Server Response: HTTP {sandboxResult.statusCode} {sandboxResult.statusText}</span>
                    <span className="text-slate-500">·</span>
                    <span>{sandboxResult.responseTimeMs} ms</span>
                  </div>
                  <h3 className="text-xl font-bold text-white break-all">
                    {sandboxResult.pageTitle}
                  </h3>
                  {sandboxResult.metaDescription && (
                    <p className="text-xs text-slate-300 mt-1 max-w-2xl line-clamp-2">
                      {sandboxResult.metaDescription}
                    </p>
                  )}
                </div>

                <div className="flex items-center gap-3 self-start md:self-auto">
                  <div className={`px-4 py-2.5 rounded-xl border text-center ${
                    sandboxResult.combinedVerdict === 'SUSPICIOUS'
                      ? 'bg-red-950/60 border-red-500/50 text-red-300'
                      : sandboxResult.combinedVerdict === 'RISKY'
                      ? 'bg-amber-950/60 border-amber-500/50 text-amber-300'
                      : 'bg-emerald-950/60 border-emerald-500/50 text-emerald-300'
                  }`}>
                    <div className="text-[10px] uppercase font-bold tracking-wider opacity-80">Combined Verdict</div>
                    <div className="text-base font-extrabold">{sandboxResult.combinedVerdict}</div>
                    <div className="text-[11px] font-mono mt-0.5">Score: {sandboxResult.combinedScore} / 100</div>
                  </div>

                  <div className="flex flex-col items-end gap-1">
                    <button
                      onClick={handleCopySandboxReport}
                      className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors border border-slate-700 cursor-pointer flex items-center gap-1.5"
                      title="Copy Full Sandbox Report"
                    >
                      {copiedSandboxReport ? (
                        <>
                          <Check className="w-4 h-4 text-teal-400" />
                          <span className="text-xs text-teal-300 font-semibold">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-4 h-4 text-teal-400" />
                          <span className="text-xs text-slate-300">Copy Report</span>
                        </>
                      )}
                    </button>
                    {sandboxCopyError && (
                      <span className="text-[11px] text-rose-400 font-medium flex items-center gap-1 bg-rose-950/60 border border-rose-800/60 px-2 py-0.5 rounded">
                        <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                        {sandboxCopyError}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Redirect Chain Inspection */}
              <div className="py-5 border-b border-slate-800">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <ArrowRight className="w-3.5 h-3.5 text-teal-400" />
                  <span>Landing Destination & Redirect Chain</span>
                </h4>
                {sandboxResult.redirectHops.length === 0 ? (
                  <div className="text-xs text-slate-400 font-mono flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Direct Connection (0 redirects) landed on: </span>
                    <span className="text-white font-bold">{sandboxResult.finalUrl}</span>
                  </div>
                ) : (
                  <div className="space-y-1.5 font-mono text-xs">
                    {sandboxResult.redirectHops.map((hop, i) => (
                      <div key={i} className="flex items-center gap-2 text-slate-400">
                        <span className="px-1.5 py-0.5 bg-slate-800 text-amber-400 rounded text-[10px]">
                          HTTP {hop.status}
                        </span>
                        <span className="text-slate-300 truncate max-w-xs">{hop.from}</span>
                        <ArrowRight className="w-3 h-3 text-slate-500 shrink-0" />
                        <span className="text-white font-bold truncate max-w-xs">{hop.to}</span>
                      </div>
                    ))}
                    <div className="text-[11px] text-amber-400 pt-1 font-sans">
                      Final landing domain: <strong className="text-white">{sandboxResult.finalUrl}</strong>
                    </div>
                  </div>
                )}
              </div>

              {/* Live Form & Credential Theft Audit */}
              <div className="py-5 border-b border-slate-800">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-teal-400" />
                  <span>DOM Forms & Credential Harvesting Audit</span>
                </h4>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                  {/* Password Input Status */}
                  <div className={`p-3.5 rounded-xl border ${
                    sandboxResult.formAnalysis.hasPasswordInput
                      ? 'bg-amber-950/30 border-amber-600/40 text-amber-200'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400'
                  }`}>
                    <div className="text-[11px] uppercase tracking-wider mb-1 font-sans">Password Input Fields</div>
                    <div className="text-sm font-bold flex items-center gap-1.5">
                      {sandboxResult.formAnalysis.hasPasswordInput ? (
                        <>
                          <AlertTriangle className="w-4 h-4 text-amber-400" />
                          <span>Detected on Page</span>
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          <span>None Found</span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* OTP / Card Inputs */}
                  <div className={`p-3.5 rounded-xl border ${
                    sandboxResult.formAnalysis.hasOtpInput || sandboxResult.formAnalysis.hasCreditCardInput
                      ? 'bg-red-950/40 border-red-600/40 text-red-200'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400'
                  }`}>
                    <div className="text-[11px] uppercase tracking-wider mb-1 font-sans">OTP & Card Fields</div>
                    <div className="text-sm font-bold flex items-center gap-1.5">
                      {sandboxResult.formAnalysis.hasOtpInput || sandboxResult.formAnalysis.hasCreditCardInput ? (
                        <>
                          <ShieldAlert className="w-4 h-4 text-red-400" />
                          <span>Sensitive Input Found</span>
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          <span>None Found</span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* External Form Action */}
                  <div className={`p-3.5 rounded-xl border ${
                    sandboxResult.formAnalysis.hasExternalFormAction
                      ? 'bg-red-950/50 border-red-500 text-red-200 shadow-md shadow-red-950'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400'
                  }`}>
                    <div className="text-[11px] uppercase tracking-wider mb-1 font-sans">Form Destination</div>
                    <div className="text-sm font-bold flex items-center gap-1.5">
                      {sandboxResult.formAnalysis.hasExternalFormAction ? (
                        <>
                          <ExternalLink className="w-4 h-4 text-red-400" />
                          <span className="text-red-400">External Domain (Harvester!)</span>
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          <span>Same Origin</span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Encryption of Submission */}
                  <div className={`p-3.5 rounded-xl border ${
                    sandboxResult.formAnalysis.insecureHttpForms
                      ? 'bg-red-950/40 border-red-500 text-red-200'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400'
                  }`}>
                    <div className="text-[11px] uppercase tracking-wider mb-1 font-sans">Form Transport Security</div>
                    <div className="text-sm font-bold flex items-center gap-1.5">
                      {sandboxResult.formAnalysis.insecureHttpForms ? (
                        <>
                          <Unlock className="w-4 h-4 text-red-400" />
                          <span>Insecure HTTP Action</span>
                        </>
                      ) : (
                        <>
                          <Lock className="w-4 h-4 text-emerald-400" />
                          <span>Encrypted (HTTPS)</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                {sandboxResult.formAnalysis.hasExternalFormAction && sandboxResult.formAnalysis.externalActionUrls.length > 0 && (
                  <div className="mt-3 p-3 rounded-xl bg-red-950/50 border border-red-500/50 text-xs text-red-300">
                    <strong>Critical Phishing Indicator:</strong> Form data is transmitted to an external server:
                    <div className="font-mono text-[11px] text-white mt-1 break-all bg-slate-950 p-2 rounded">
                      {sandboxResult.formAnalysis.externalActionUrls.join(', ')}
                    </div>
                  </div>
                )}
              </div>

              {/* On-Page Social Engineering Signals */}
              {sandboxResult.contentScamSignals.warningSigns.length > 0 && (
                <div className="py-5 border-b border-slate-800">
                  <h4 className="text-xs font-bold text-red-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                    <span>On-Page Social Engineering Content Detected (Score: {sandboxResult.contentScamSignals.detectedScore}/100)</span>
                  </h4>
                  <p className="text-xs text-slate-300 mb-3">
                    ScamLens analyzed the visible text content on the target web page and identified the following fraud patterns:
                  </p>
                  <div className="space-y-2">
                    {sandboxResult.contentScamSignals.warningSigns.map((w) => (
                      <div key={w.id} className="p-3 rounded-lg bg-red-950/30 border border-red-800/40 text-xs">
                        <div className="font-bold text-red-300">{w.title}</div>
                        <p className="text-slate-300 mt-0.5">{w.explanation}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Security Headers Summary */}
              <div className="pt-5">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-teal-400" />
                  <span>Security Headers & Server Audit</span>
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase font-sans">HSTS</div>
                    <div className={`font-bold ${sandboxResult.securityHeaders.hsts ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {sandboxResult.securityHeaders.hsts ? 'Enforced' : 'Missing'}
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase font-sans">CSP</div>
                    <div className={`font-bold ${sandboxResult.securityHeaders.contentSecurityPolicy ? 'text-emerald-400' : 'text-amber-400'}`}>
                      {sandboxResult.securityHeaders.contentSecurityPolicy ? 'Published' : 'Missing'}
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase font-sans">X-Frame-Options</div>
                    <div className="font-bold text-slate-300 truncate" title={sandboxResult.securityHeaders.xFrameOptions || 'None'}>
                      {sandboxResult.securityHeaders.xFrameOptions || 'Not set'}
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase font-sans">Server Info</div>
                    <div className="font-bold text-slate-300 truncate" title={sandboxResult.securityHeaders.server || 'Hidden'}>
                      {sandboxResult.securityHeaders.server || 'Hidden'}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* STRUCTURAL / SYNTAX RESULTS CONTAINER                                     */}
        {/* ========================================================================= */}
        {result && (
          <div className="mt-8 space-y-6">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <FileCode className="w-4 h-4 text-teal-400" />
                <span>Structural Syntax & Domain Architecture Inspection</span>
              </h3>
              <div className="flex flex-col items-end gap-1">
                <button
                  onClick={handleCopyReport}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors flex items-center gap-1.5 cursor-pointer"
                  title="Copy plain-text syntax report to clipboard"
                >
                  {copiedReport ? <Check className="w-3.5 h-3.5 text-teal-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedReport ? 'Copied Report' : 'Copy Syntax Report'}</span>
                </button>
                {copyError && (
                  <span className="text-[11px] text-rose-400 font-medium flex items-center gap-1 bg-rose-950/60 border border-rose-800/60 px-2 py-0.5 rounded">
                    <AlertTriangle className="w-3 h-3 text-rose-400 shrink-0" />
                    {copyError}
                  </span>
                )}
              </div>
            </div>

            {/* 1. Verdict & Risk Gauge */}
            {(() => {
              const styles = getVerdictStyles(result.verdict);
              const VerdictIcon = styles.icon;

              return (
                <div className={`p-6 sm:p-8 rounded-2xl border ${styles.bg} shadow-lg transition-all`}>
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
                    <div className="lg:col-span-5 space-y-3">
                      <div className="flex items-center gap-2">
                        <span className={`px-2.5 py-1 rounded-md text-xs font-extrabold uppercase tracking-wider ${styles.badgeBg}`}>
                          {styles.label}
                        </span>
                        <span className="text-xs text-slate-400 font-mono">
                          Score: {result.riskScore} / 100
                        </span>
                      </div>

                      {/* Progress Meter */}
                      <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden border border-slate-800">
                        <div
                          className={`h-full ${styles.barColor} transition-all duration-500`}
                          style={{ width: `${Math.max(4, result.riskScore)}%` }}
                        />
                      </div>
                    </div>

                    <div className="lg:col-span-7 lg:border-l lg:border-slate-800/80 lg:pl-8 space-y-2">
                      <div className="flex items-start gap-2.5">
                        <VerdictIcon className="w-5 h-5 shrink-0 mt-0.5" />
                        <div>
                          <h4 className="text-sm font-bold text-white">Structural Risk Summary</h4>
                          <p className="text-xs text-slate-300 leading-relaxed mt-0.5">
                            {result.summary}
                          </p>
                        </div>
                      </div>

                      <div className="text-xs text-slate-400 font-mono break-all pt-2">
                        Normalized: <span className="text-teal-400">{result.normalizedUrl}</span>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* 2. Deconstructed URL Anatomy */}
            <div className="bg-slate-900 rounded-2xl border border-slate-800 p-6 sm:p-8">
              <h3 className="text-base font-bold text-white mb-4 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-teal-400" />
                <span>Deconstructed URL Anatomy</span>
              </h3>

              <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <div className="text-[11px] text-slate-500 uppercase font-sans mb-1">Protocol</div>
                  <div className={`font-bold ${result.protocol === 'https' ? 'text-emerald-400' : 'text-rose-400'}`}>
                    {result.protocol}://
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <div className="text-[11px] text-slate-500 uppercase font-sans mb-1">Root Domain</div>
                  <div className="font-bold text-white truncate" title={result.rootDomain}>
                    {result.rootDomain}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <div className="text-[11px] text-slate-500 uppercase font-sans mb-1">Effective Suffix</div>
                  <div className="font-bold text-teal-400">.{result.effectiveTld || 'none'}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800">
                  <div className="text-[11px] text-slate-500 uppercase font-sans mb-1">Host Type</div>
                  <div className="font-bold text-slate-300">
                    {result.isIpAddress ? 'Numeric IP' : 'Named Host'}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 col-span-2 md:col-span-1">
                  <div className="text-[11px] text-slate-500 uppercase font-sans mb-1">Full Hostname</div>
                  <div className="font-bold text-slate-200 truncate" title={result.hostname}>
                    {result.hostname}
                  </div>
                </div>
              </div>

              {result.pathname && result.pathname !== '/' && (
                <div className="mt-3 p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs font-mono text-slate-300">
                  <span className="text-slate-500 font-sans">Path: </span>
                  <span className="text-slate-200">{result.pathname}</span>
                  {result.searchParams && (
                    <span className="text-amber-400/80">{result.searchParams}</span>
                  )}
                </div>
              )}
            </div>

            {/* 3. Structural Flags Detected */}
            <div className="bg-slate-900 rounded-2xl border border-slate-800 p-6 sm:p-8">
              <h3 className="text-base font-bold text-white mb-4">
                Structural Findings & Indicators ({result.flags.length})
              </h3>

              {result.warningCount === 0 && (
                <div className="p-5 rounded-xl bg-slate-950/60 border border-slate-800 text-center space-y-2 mb-4">
                  <CheckCircle2 className="w-7 h-7 text-emerald-400 mx-auto" />
                  <div className="text-xs sm:text-sm font-semibold text-slate-200">
                    No Structural Red Flags Detected
                  </div>
                  <p className="text-xs text-slate-400 max-w-md mx-auto">
                    The URL syntax does not trigger common phishing red flags such as raw IP addresses, abusive disposable TLDs, or masked shorteners.
                  </p>
                </div>
              )}

              {result.flags.length > 0 && (
                <div className="space-y-3">
                  {result.flags.map((flag) => {
                    const isInfo = flag.severity === 'info';
                    return (
                      <div
                        key={flag.id}
                        className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/90 space-y-2"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm font-bold text-white flex items-center gap-2">
                            {isInfo ? (
                              <CheckCircle2 className="w-4 h-4 text-teal-400 shrink-0" />
                            ) : (
                              <AlertTriangle
                                className={`w-4 h-4 shrink-0 ${
                                  flag.severity === 'critical'
                                    ? 'text-red-400'
                                    : flag.severity === 'high'
                                    ? 'text-amber-400'
                                    : 'text-teal-400'
                                }`}
                              />
                            )}
                            <span>{flag.name}</span>
                          </span>
                          <span
                            className={`text-[11px] font-mono uppercase px-2 py-0.5 rounded ${
                              isInfo
                                ? 'bg-teal-950/70 text-teal-400 border border-teal-800/60'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {isInfo ? 'Trust Signal' : flag.severity}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed">{flag.description}</p>
                        <p className="text-xs text-slate-400 pt-1 border-t border-slate-900 leading-relaxed">
                          {flag.detail}
                        </p>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
