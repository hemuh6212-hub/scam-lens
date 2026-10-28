/**
 * ScamLens Type Definitions
 */

export type RiskLevel = 'SAFE' | 'RISKY' | 'SCAM';

export interface WarningSign {
  id: string;
  category: string;
  title: string;
  points: number;
  explanation: string;
  matchedSnippets: string[];
  recommendation: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface MessageAnalysisResult {
  score: number;
  verdict: RiskLevel;
  verdictSummary: string;
  warningSigns: WarningSign[];
  recommendations: string[];
  extractedUrls: string[];
  totalAnalyzedWords: number;
  analysisTimestamp: string;
}

export type UrlRiskLevel = 'SAFE' | 'RISKY' | 'SUSPICIOUS';

export interface UrlFlag {
  id: string;
  name: string;
  severity: 'info' | 'warning' | 'high' | 'critical';
  description: string;
  detail: string;
}

export interface UrlAnalysisResult {
  inputUrl: string;
  normalizedUrl: string;
  isValid: boolean;
  verdict: UrlRiskLevel;
  riskScore: number; // 0 to 100
  warningCount: number;
  summary: string;
  protocol: string;
  hostname: string;
  rootDomain: string;
  effectiveTld: string;
  pathname: string;
  searchParams: string;
  tld: string;
  isIpAddress: boolean;
  flags: UrlFlag[];
  recommendations: string[];
  analysisTimestamp: string;
}

export interface MessageSample {
  id: string;
  title: string;
  type: string;
  badgeColor: string;
  description: string;
  text: string;
}

export interface UrlSample {
  id: string;
  label: string;
  url: string;
  category: string;
}

export interface SandboxScanResult {
  targetUrl: string;
  finalUrl: string;
  statusCode: number;
  statusText: string;
  responseTimeMs: number;
  redirectHops: Array<{ from: string; to: string; status: number }>;
  pageTitle: string;
  metaDescription: string;
  isLive: boolean;
  securityHeaders: {
    hsts: boolean;
    contentSecurityPolicy: boolean;
    xFrameOptions: string | null;
    server: string | null;
  };
  formAnalysis: {
    totalForms: number;
    hasPasswordInput: boolean;
    hasOtpInput: boolean;
    hasCreditCardInput: boolean;
    hasExternalFormAction: boolean;
    externalActionUrls: string[];
    insecureHttpForms: boolean;
  };
  scriptAnalysis: {
    externalScriptCount: number;
    iframeCount: number;
    iframeSources: string[];
  };
  contentScamSignals: {
    detectedScore: number;
    warningSigns: Array<{ id: string; title: string; category: string; severity: string; explanation: string }>;
    matchedSnippets: string[];
  };
  sandboxFlags: UrlFlag[];
  sandboxScore: number;
  combinedScore: number;
  combinedVerdict: UrlRiskLevel;
  summary: string;
  recommendations: string[];
  timestamp: string;
}
