import { useState, useRef, useEffect, useCallback } from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import { Mail, FileText, Server, UploadCloud, Loader2, CheckCircle, XCircle, AlertTriangle, ShieldOff, ShieldCheck, ArrowRight, ArrowLeft } from 'lucide-react';
import { IngestedEmailsList } from '../components/email/IngestedEmailsList';
import { ForensicTimeline } from '../components/ForensicTimeline';
import { SeverityBadge } from '../components/threats/SeverityBadge';
import { ThreatPriorityExplanation } from '../components/threat/ThreatPriorityExplanation';
import { ChainOfCustody } from '../components/evidence/ChainOfCustody';
import { UnifiedForensicTimeline } from '../components/timeline/UnifiedForensicTimeline';
import { EvidenceGraphView } from '../components/EvidenceGraphView';
import { ReportsPanel } from '../components/ReportsPanel';
import { apiClient } from '../lib/apiClient';
import { aggregateEmailForensics } from '../features/email-forensics/aggregateEmailForensics';
import type { EmailForensicsData, ThreatPriority } from '@ciperscope/types';

const PRIORITY_STYLES: Record<ThreatPriority, string> = {
  P1: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
  P2: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
  P3: 'bg-slate-700/50 text-slate-300 border-slate-600/50',
};

export const EmailAnalysis = () => {
  const { id: routeEmailId } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  // GET /emails/:id/analysis now returns the real caseId (Phase 3, Step 2 —
  // previously a documented missing backend capability). This override
  // param is only for the rare case a caller wants to force a different
  // case context than the one recorded on the email itself.
  const caseIdOverride = searchParams.get('caseId');

  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<{ message?: string; error?: string; duplicate?: boolean; emailId?: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [analysisStatus, setAnalysisStatus] = useState<string | null>(null);
  const [data, setData] = useState<EmailForensicsData | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const activeEmailId = routeEmailId || uploadResult?.emailId;

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setUploadResult(null);
    setData(null);
    setAnalysisStatus(null);
    setLoadError(null);

    try {
      const result = await apiClient.ingestEmail(file);
      setUploadResult(result);
    } catch (err) {
      setUploadResult({ error: err instanceof Error ? err.message : 'Upload failed' });
    } finally {
      setUploading(false);
    }
  };

  const loadForensics = useCallback(async (emailId: string) => {
    try {
      const forensics = await aggregateEmailForensics(emailId, caseIdOverride);
      setData(forensics);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load email forensics');
    }
  }, [caseIdOverride]);

  useEffect(() => {
    if (!activeEmailId) return;

    let cancelled = false;
    let interval: ReturnType<typeof setInterval>;

    const poll = async () => {
      try {
        const summary = await apiClient.getEmailAnalysis(activeEmailId);
        if (cancelled) return;
        setAnalysisStatus(summary.analysisStatus);

        if (summary.analysisStatus === 'COMPLETED') {
          clearInterval(interval);
          await loadForensics(activeEmailId);
        } else if (summary.analysisStatus === 'FAILED') {
          clearInterval(interval);
          setLoadError('Analysis failed on the backend.');
        }
      } catch (err) {
        if (!cancelled) setLoadError(err instanceof Error ? err.message : 'Failed to load email');
      }
    };

    interval = setInterval(poll, 2000);
    poll();

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [activeEmailId, loadForensics]);

  const getHeader = (name: string) => data?.headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;

  const priority = data?.threat.priority;
  const severity = data?.threat.score.severity;

  return (
    <div className="space-y-6 pb-20">

      {activeEmailId && (
        <div className="flex items-center justify-between">
          <Link
            to="/email-analysis"
            onClick={() => {
              setUploadResult(null);
              setData(null);
              setAnalysisStatus(null);
              setLoadError(null);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-medium text-slate-300 hover:text-indigo-400 hover:border-slate-700 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Ingested Emails</span>
          </Link>
          <div className="text-xs text-slate-500 font-mono truncate max-w-md">
            ID: {activeEmailId}
          </div>
        </div>
      )}

      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100 flex items-center">
            <Mail className="w-6 h-6 mr-3 text-slate-400" />
            {activeEmailId ? 'Email Forensics' : 'Email Analysis & Ingested Inbox'}
          </h1>
          <p className="text-slate-400 mt-1">
            {activeEmailId
              ? 'Detailed forensics, threat scoring, and prioritization for the selected email artifact.'
              : 'Real-time stream of Gmail-ingested and uploaded emails ready for forensic analysis.'}
          </p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex flex-col items-end">
            <input
               type="file"
               ref={fileInputRef}
               className="hidden"
               accept=".eml"
               onChange={handleFileUpload}
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg font-medium text-sm flex items-center transition-colors disabled:opacity-50"
            >
              {uploading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <UploadCloud className="w-4 h-4 mr-2" />}
              {uploading ? 'Ingesting...' : 'Ingest Raw Email'}
            </button>
            {uploadResult && (
               <div className={`text-xs mt-2 ${uploadResult.error ? 'text-rose-400' : (uploadResult.duplicate ? 'text-amber-400' : 'text-emerald-400')}`}>
                 {uploadResult.error || uploadResult.message}
               </div>
            )}
          </div>
          {data && priority && (
            <div className="flex items-center gap-3">
              <span className={`text-xs px-2.5 py-1.5 rounded font-bold border ${PRIORITY_STYLES[priority.priority]}`} title={priority.reasons.join('; ')}>
                {priority.priority}
              </span>
              {severity && <SeverityBadge level={severity} className="px-2.5 py-1.5 text-xs font-bold" />}
            </div>
          )}
          {activeEmailId && !data && (
             <div className="text-right flex items-center gap-3">
               <div className="text-sm font-medium text-slate-400">Status</div>
               {analysisStatus === 'PROCESSING' || analysisStatus === 'PENDING' || !analysisStatus ? (
                  <Loader2 className="w-5 h-5 animate-spin text-indigo-400" />
               ) : analysisStatus === 'FAILED' ? (
                  <XCircle className="w-5 h-5 text-rose-500" />
               ) : (
                  <CheckCircle className="w-5 h-5 text-emerald-500" />
               )}
             </div>
          )}
        </div>
      </div>

      {!activeEmailId && (
        <IngestedEmailsList />
      )}

      {loadError && (
        <div className="p-4 text-sm text-rose-400 border border-rose-900/50 bg-rose-950/20 rounded-lg">
          {loadError}
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">

            {/* Threat Assessment */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
                <h2 className="font-medium text-slate-200">Threat Assessment</h2>
                {severity && (
                  <span className="flex items-center gap-1.5 text-xs text-slate-400">
                    <SeverityBadge level={severity} />
                    (Score: {data.threat.score.value ?? 'N/A'}/100)
                  </span>
                )}
              </div>
              <div className="p-5 space-y-4">
                {priority && data && (
                  <ThreatPriorityExplanation
                    priority={priority}
                    threatScore={data.threat.score.value}
                    severity={data.threat.score.severity}
                    maliciousIndicatorCount={data.threat.maliciousIndicatorCount}
                    authenticationFailed={data.threat.authenticationFailed}
                    dkimFailed={data.threat.dkimFailed}
                    mlClassification={data.threat.mlClassification}
                  />
                )}
                <h3 className="text-sm font-medium text-slate-300 mb-2 border-b border-slate-800 pb-2">Explainable Risk Factors</h3>
                {data.threat.score.factors.length > 0 ? (
                  <div className="space-y-3">
                    {data.threat.score.factors.map((f, i) => (
                      <div key={i} className="bg-slate-950 border border-slate-800 rounded p-3 text-xs flex flex-col space-y-2">
                        <div className="flex justify-between items-center">
                          <span className="font-mono text-amber-400 font-semibold">{f.category}</span>
                          <span className="text-slate-500">+{f.scoreContribution} Score</span>
                        </div>
                        <div className="text-slate-300">{f.description}</div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-slate-500">No elevated risk factors identified.</div>
                )}
              </div>
            </div>

            {/* Timeline */}
            <ForensicTimeline
              analysis={data.email}
              headers={data.headers}
              spf={data.authentication.spf}
              dkim={data.authentication.dkim}
              dmarc={data.authentication.dmarc}
              urls={data.urls}
              mlInference={{ status: data.threat.mlStatus, prediction: data.threat.mlClassification }}
            />

            {/* Header Forensics */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
                <h2 className="font-medium text-slate-200">Overview</h2>
                <span className="text-xs bg-slate-800 text-slate-300 px-2 py-1 rounded">Parsed</span>
              </div>
              <div className="p-5 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="text-sm text-slate-400">From</div>
                  <div className="md:col-span-3 text-sm font-medium text-slate-200">{getHeader('from') || 'N/A'}</div>

                  <div className="text-sm text-slate-400">To</div>
                  <div className="md:col-span-3 text-sm text-slate-200">{getHeader('to') || 'N/A'}</div>

                  <div className="text-sm text-slate-400">Subject</div>
                  <div className="md:col-span-3 text-sm text-slate-200">{getHeader('subject') || 'N/A'}</div>

                  <div className="text-sm text-slate-400">Date</div>
                  <div className="md:col-span-3 text-sm text-slate-200">{getHeader('date') || 'N/A'}</div>

                  <div className="text-sm text-slate-400">Message-ID</div>
                  <div className="md:col-span-3 text-sm text-slate-400 font-mono break-all">{getHeader('message-id') || 'N/A'}</div>
                </div>
              </div>
            </div>

            {/* Transport Trace */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50">
                <h2 className="font-medium text-slate-200">Transport Trace (Received Hops)</h2>
              </div>
              <div className="p-5">
                <div className="flex flex-col space-y-6 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-slate-800">
                  {data.relayHops.map((hop, idx) => (
                    <div key={idx} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                      <div className="flex items-center justify-center w-10 h-10 rounded-full border border-slate-700 bg-slate-900 text-slate-400 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2">
                        <Server className="w-5 h-5" />
                      </div>
                      <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] p-4 rounded-lg border border-slate-800 bg-slate-950/50">
                        <div className="flex items-center justify-between mb-1">
                          <div className="font-medium text-sm text-slate-200">Hop {idx}</div>
                          {hop.sourceIp && <span className="text-xs text-slate-400 font-medium font-mono">{hop.sourceIp}</span>}
                        </div>
                        <div className="text-xs text-slate-500 line-clamp-3" title={hop.receivedHeader}>{hop.receivedHeader}</div>
                      </div>
                    </div>
                  ))}
                  {data.relayHops.length === 0 && <div className="text-sm text-slate-500 text-center w-full">No Received hops detected.</div>}
                </div>
              </div>
            </div>

            {/* Authentication */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
                <h2 className="font-medium text-slate-200">Authentication (SPF / DKIM / DMARC)</h2>
                <span className="text-xs bg-indigo-500/20 text-indigo-400 px-2 py-1 rounded border border-indigo-500/30">DNS-based</span>
              </div>
              <div className="p-5 space-y-4">

                 {data.authentication.summary && (
                   <div className={`p-4 rounded-lg border ${data.authentication.summary.isConsistent ? 'border-emerald-900/50 bg-emerald-950/20' : 'border-rose-900/50 bg-rose-950/20'}`}>
                     <div className="flex items-center gap-2 mb-2">
                       {data.authentication.summary.isConsistent ? <CheckCircle className="w-5 h-5 text-emerald-500" /> : <XCircle className="w-5 h-5 text-rose-500" />}
                       <h3 className="font-semibold text-slate-200">Forensic Consistency Check</h3>
                     </div>
                     <p className="text-sm text-slate-400">{data.authentication.summary.summary}</p>
                   </div>
                 )}

                 <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* SPF */}
                    <div className="border border-slate-800 bg-slate-950 rounded p-4">
                       <h3 className="text-sm font-medium text-slate-300 mb-2 border-b border-slate-800 pb-2">SPF</h3>
                       {data.authentication.spf.length > 0 ? data.authentication.spf.map((s, i) => (
                         <div key={i} className="text-xs space-y-1">
                           <div className="flex justify-between">
                             <span className="text-slate-500">Result</span>
                             <span className={`font-mono font-bold ${s.result === 'PASS' ? 'text-emerald-400' : (s.result === 'NONE' ? 'text-slate-400' : 'text-rose-400')}`}>{s.result}</span>
                           </div>
                           <div className="flex justify-between"><span className="text-slate-500">Domain</span><span className="text-slate-300 truncate max-w-[120px]">{s.domain || '-'}</span></div>
                           <div className="flex justify-between"><span className="text-slate-500">Evaluated IP</span><span className="text-slate-300">{s.evaluatedIp || '-'}</span></div>
                           <div className="mt-2 text-slate-500 italic break-words">{s.explanation}</div>
                         </div>
                       )) : <div className="text-xs text-slate-600">No SPF data</div>}
                    </div>

                    {/* DKIM — badge and banner reflect each signature's REAL cryptographicallyVerified flag (Phase 8) */}
                    <div className={`border rounded p-4 bg-slate-950 ${data.authentication.dkim.some(d => d.cryptographicallyVerified) ? 'border-emerald-900/40' : 'border-slate-800'}`}>
                       <h3 className="text-sm font-medium text-slate-300 mb-2 border-b border-slate-800 pb-2 flex items-center gap-1.5">
                         DKIM
                         {data.authentication.dkim.some(d => d.cryptographicallyVerified) ? (
                           <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
                         ) : (
                           <ShieldOff className="w-3.5 h-3.5 text-amber-500" />
                         )}
                       </h3>
                       {data.authentication.dkim.length > 0 ? data.authentication.dkim.map((d, i) => (
                         <div key={i} className="text-xs space-y-1 pb-2 mb-2 border-b border-slate-800/50 last:border-0 last:pb-0 last:mb-0">
                           {d.cryptographicallyVerified ? (
                             <div className="mb-1 p-2 bg-emerald-950/30 border border-emerald-900/40 rounded text-[11px] text-emerald-400 flex items-start gap-1.5">
                               <ShieldCheck className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                               <span>CRYPTOGRAPHICALLY VERIFIED — the signature was independently validated against the signer's published public key.</span>
                             </div>
                           ) : (
                             <div className="mb-1 p-2 bg-amber-950/30 border border-amber-900/40 rounded text-[11px] text-amber-400 flex items-start gap-1.5">
                               <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                               <span>NOT VERIFIED — cryptographic signature verification did not succeed; this is not proof of authenticity.</span>
                             </div>
                           )}
                           <div className="flex justify-between">
                             <span className="text-slate-500">Result</span>
                             <span className={`font-mono font-bold ${d.result === 'PASS' ? 'text-emerald-400' : (d.result === 'NONE' ? 'text-slate-400' : 'text-rose-400')}`}>{d.result}</span>
                           </div>
                           <div className="flex justify-between"><span className="text-slate-500">Domain</span><span className="text-slate-300 truncate max-w-[120px]">{d.domain || '-'}</span></div>
                           <div className="flex justify-between"><span className="text-slate-500">Selector</span><span className="text-slate-300 truncate max-w-[120px]">{d.selector || '-'}</span></div>
                           <div className="mt-2 text-slate-500 italic break-words">{d.explanation}</div>
                         </div>
                       )) : <div className="text-xs text-slate-600">No DKIM data</div>}
                    </div>

                    {/* DMARC */}
                    <div className="border border-slate-800 bg-slate-950 rounded p-4">
                       <h3 className="text-sm font-medium text-slate-300 mb-2 border-b border-slate-800 pb-2">DMARC</h3>
                       {data.authentication.dmarc ? (
                         <div className="text-xs space-y-1">
                           <div className="flex justify-between">
                             <span className="text-slate-500">Result</span>
                             <span className={`font-mono font-bold ${data.authentication.dmarc.result === 'PASS' ? 'text-emerald-400' : (data.authentication.dmarc.result === 'NONE' ? 'text-slate-400' : 'text-rose-400')}`}>{data.authentication.dmarc.result}</span>
                           </div>
                           <div className="flex justify-between"><span className="text-slate-500">Org Domain</span><span className="text-slate-300">{data.authentication.dmarc.orgDomain || '-'}</span></div>
                           <div className="flex justify-between"><span className="text-slate-500">Policy</span><span className="text-slate-300">{data.authentication.dmarc.policy || '-'}</span></div>
                           <div className="flex justify-between"><span className="text-slate-500">Alignment</span><span className="text-slate-300">SPF:{data.authentication.dmarc.spfAlignment?.charAt(0).toUpperCase()} DKIM:{data.authentication.dmarc.dkimAlignment?.charAt(0).toUpperCase()}</span></div>
                           <div className="mt-2 text-slate-500 italic break-words">{data.authentication.dmarc.explanation}</div>
                         </div>
                       ) : <div className="text-xs text-slate-600">No DMARC data</div>}
                    </div>
                 </div>
              </div>
            </div>

            {/* URL & Attachment Intelligence */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
                <h2 className="font-medium text-slate-200">URL &amp; Attachment Intelligence</h2>
                <span className="text-xs bg-rose-500/20 text-rose-400 px-2 py-1 rounded border border-rose-500/30">Passive Scan</span>
              </div>
              <div className="p-5 space-y-6">

                <div>
                   <h3 className="text-sm font-medium text-slate-300 mb-3 border-b border-slate-800 pb-2">Extracted URLs ({data.urls.length})</h3>
                   <div className="space-y-3">
                     {data.urls.length > 0 ? data.urls.map((u, i) => (
                       <div key={i} className="bg-slate-950 border border-slate-800 rounded p-3 text-xs flex flex-col space-y-2">
                         <div className="flex justify-between items-start">
                           <div className="font-mono text-slate-300 break-all pr-4">{u.url}</div>
                           <span className="bg-slate-800 text-slate-400 px-2 py-0.5 rounded flex-shrink-0">SRC: {u.source}</span>
                         </div>
                         {u.normalizedUrl && u.normalizedUrl !== u.url && (
                           <div className="text-slate-500 font-mono break-all"><span className="text-slate-600 mr-2">NORMALIZED:</span>{u.normalizedUrl}</div>
                         )}
                         {((u.indicators?.length ?? 0) > 0 || u.isObfuscated) && (
                           <div className="flex gap-2 mt-1 flex-wrap">
                             {u.isObfuscated && <span className="text-rose-400 border border-rose-500/30 bg-rose-500/10 px-1 rounded">OBFUSCATED</span>}
                             {u.indicators?.map((ind, idx) => (
                               <span key={idx} className="text-amber-400 border border-amber-500/30 bg-amber-500/10 px-1 rounded">{ind}</span>
                             ))}
                           </div>
                         )}
                       </div>
                     )) : <div className="text-xs text-slate-600">No URLs extracted</div>}
                   </div>
                </div>

                <div>
                   <h3 className="text-sm font-medium text-slate-300 mb-3 border-b border-slate-800 pb-2">Attachment Analysis ({data.attachments.length})</h3>
                   <div className="space-y-3">
                     {data.attachments.length > 0 ? data.attachments.map((a, i) => (
                       <div key={i} className="bg-slate-950 border border-slate-800 rounded p-3 text-xs flex flex-col space-y-2">
                         <div className="flex justify-between items-center">
                           <div className="font-medium text-slate-200">{a.filename}</div>
                           <div className="text-slate-500">{Math.round(a.sizeBytes / 1024)} KB</div>
                         </div>
                         <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
                            <div className="flex justify-between p-1 bg-slate-900 rounded"><span className="text-slate-500">Declared MIME</span><span className="text-slate-300">{a.mimeType}</span></div>
                            <div className="flex justify-between p-1 bg-slate-900 rounded"><span className="text-slate-500">Actual MIME</span><span className={`font-mono ${a.isMismatch ? 'text-rose-400' : 'text-slate-300'}`}>{a.actualMimeType || 'Unknown'}</span></div>
                         </div>
                         {a.isMismatch && (
                            <div className="text-rose-400 border border-rose-500/30 bg-rose-500/10 px-2 py-1 rounded w-fit mt-1">
                              SUSPICIOUS: File signature mismatch
                            </div>
                         )}
                         {a.sha256 && (
                            <div className="text-slate-500 font-mono"><span className="text-slate-600 mr-2">SHA-256:</span>{a.sha256}</div>
                         )}
                         {a.threatIndicators && a.threatIndicators.length > 0 && (
                           <div className="flex flex-wrap gap-1 mt-1">
                             {a.threatIndicators.map((ind, ti) => (
                               <span
                                 key={ti}
                                 title={ind.description}
                                 className={`px-1.5 py-0.5 rounded border text-[10px] ${
                                   ind.severity === 'CRITICAL' ? 'text-rose-400 border-rose-500/30 bg-rose-500/10' :
                                   ind.severity === 'HIGH' ? 'text-amber-400 border-amber-500/30 bg-amber-500/10' :
                                   ind.severity === 'MEDIUM' ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10' :
                                   'text-slate-400 border-slate-600/30 bg-slate-600/10'
                                 }`}
                               >
                                 {ind.category}
                               </span>
                             ))}
                           </div>
                         )}
                         {a.apkMetadata && (
                           <div className="bg-slate-900 border border-slate-800 rounded p-2 mt-1 space-y-1">
                             <div className="text-amber-400 font-medium">Android APK — Static Analysis</div>
                             <div className="grid grid-cols-2 gap-1 text-slate-400">
                               <div>Package: <span className="text-slate-300">{a.apkMetadata.packageName ?? 'unknown'}</span></div>
                               <div>Version: <span className="text-slate-300">{a.apkMetadata.versionName ?? 'unknown'}</span></div>
                               <div>Min/Target SDK: <span className="text-slate-300">{a.apkMetadata.minSdkVersion ?? '?'}/{a.apkMetadata.targetSdkVersion ?? '?'}</span></div>
                               <div>Signed: <span className="text-slate-300">{(a.apkMetadata.signing.hasV1JarSigning || a.apkMetadata.signing.hasV2SigningBlock) ? 'Yes' : 'No'}</span></div>
                             </div>
                             {a.apkMetadata.suspiciousPermissions.length > 0 && (
                               <div className="text-rose-400">Suspicious permissions: {a.apkMetadata.suspiciousPermissions.join(', ')}</div>
                             )}
                             {a.apkMetadata.manifestParseError && (
                               <div className="text-rose-400">Manifest parse error: {a.apkMetadata.manifestParseError}</div>
                             )}
                           </div>
                         )}
                         {a.qrFindings && a.qrFindings.detected && (
                           <div className="bg-slate-900 border border-slate-800 rounded p-2 mt-1 space-y-1">
                             <div className="text-cyan-400 font-medium">QR Code Analysis ({a.qrFindings.codes.length} detected)</div>
                             <div className="space-y-1">
                               {a.qrFindings.codes.map((code, ci) => (
                                 <div key={ci} className="bg-slate-950 border border-slate-800 rounded p-2">
                                   <div className="flex justify-between items-start">
                                     <span className="text-slate-500">Type: <span className="text-slate-300">{code.type}</span></span>
                                   </div>
                                   <div className="font-mono text-slate-300 break-all mt-1">{code.payload}</div>
                                   {code.type === 'URL' && (
                                     <div className="text-slate-600 mt-1">Extracted URL — see full threat findings under "Extracted URLs" above</div>
                                   )}
                                 </div>
                               ))}
                             </div>
                             {a.qrFindings.errors && a.qrFindings.errors.length > 0 && (
                               <div className="text-rose-400">QR analysis notice: {a.qrFindings.errors.join(', ')}</div>
                             )}
                           </div>
                         )}
                       </div>
                     )) : <div className="text-xs text-slate-600">No attachments found</div>}
                   </div>
                </div>
              </div>
            </div>

            {/* AI Explanation */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
                <h2 className="font-medium text-slate-200">AI / ML Explanation</h2>
                <span className="text-xs bg-indigo-500/20 text-indigo-400 px-2 py-1 rounded border border-indigo-500/30">DistilBERT Inference</span>
              </div>
              <div className="p-5 space-y-4">
                {!data.threat.mlStatus || data.threat.mlStatus === 'NOT_AVAILABLE' ? (
                  <div className="bg-slate-950 border border-slate-800 rounded p-4 text-sm flex flex-col space-y-2">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-slate-400 font-medium">Status</span>
                      <span className="text-amber-400 font-mono">MODEL NOT AVAILABLE</span>
                    </div>
                    <div className="text-slate-500 italic">No verified classification model is currently configured.</div>
                  </div>
                ) : (
                  <div className="bg-slate-950 border border-slate-800 rounded p-4 text-sm flex flex-col space-y-2">
                    <div className="flex justify-between items-center border-b border-slate-800/50 pb-2 mb-2">
                      <span className="text-slate-400 font-medium">Classification</span>
                      <span className={`font-bold ${data.threat.mlClassification === 'PHISHING' || data.threat.mlClassification === 'BEC' ? 'text-rose-400' : 'text-emerald-400'}`}>{data.threat.mlClassification || 'UNKNOWN'}</span>
                    </div>
                    <div className="text-xs text-slate-500">
                      This is an automated model assessment, not independent confirmation. See Threat Assessment above for the explainable risk factors that also feed the priority calculation.
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Threat Intelligence / CTI */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
                <h2 className="font-medium text-slate-200">Indicators &amp; Threat Intelligence (CTI)</h2>
                <div className="flex items-center gap-3">
                  <Link to="/indicators" className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1">
                    View org-wide <ArrowRight className="w-3 h-3" />
                  </Link>
                  <span className="text-xs bg-rose-500/20 text-rose-400 px-2 py-1 rounded border border-rose-500/30">AbuseIPDB / VirusTotal</span>
                </div>
              </div>
              <div className="p-5">
                 {data.indicators.length > 0 ? (
                   <div className="space-y-3">
                     {data.indicators.map((ti, i) => (
                       <Link
                         key={i}
                         to={`/indicators?q=${encodeURIComponent(ti.iocValue)}`}
                         className="block bg-slate-950 border border-slate-800 rounded p-3 text-sm flex flex-col space-y-2 hover:border-blue-600/50 transition-colors"
                       >
                         <div className="flex justify-between items-center border-b border-slate-800/50 pb-2 mb-1">
                           <span className="font-mono text-slate-300 break-all">{ti.iocValue}</span>
                           <span className={`text-xs px-2 py-1 rounded font-bold ${ti.status === 'MALICIOUS' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : (ti.status === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 'bg-slate-800 text-slate-400')}`}>{ti.status}</span>
                         </div>
                         <div className="grid grid-cols-2 gap-2 text-xs">
                           <div className="flex justify-between p-1 bg-slate-900 rounded"><span className="text-slate-500">Type</span><span className="text-slate-300">{ti.iocType}</span></div>
                           <div className="flex justify-between p-1 bg-slate-900 rounded"><span className="text-slate-500">Source</span><span className="text-slate-300">{ti.provider}</span></div>
                           <div className="flex justify-between p-1 bg-slate-900 rounded"><span className="text-slate-500">Confidence</span><span className="text-slate-300">{ti.confidence ? `${ti.confidence}%` : 'N/A'}</span></div>
                         </div>
                       </Link>
                     ))}
                   </div>
                 ) : (
                   <div className="text-sm text-slate-500 text-center py-2">No Threat Intelligence indicators found</div>
                 )}
              </div>
            </div>

            {/* IP & Domain Intelligence (Phase H) */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
                <h2 className="font-medium text-slate-200">IP &amp; Domain Intelligence</h2>
                <span className="text-xs bg-indigo-500/20 text-indigo-400 px-2 py-1 rounded border border-indigo-500/30">Approximate network geolocation</span>
              </div>
              <div className="p-5">
                 {data.geolocation.length > 0 ? (
                   <div className="space-y-3">
                     {data.geolocation.map((geo, i) => (
                       <div key={i} className="bg-slate-950 border border-slate-800 rounded p-3 text-sm flex flex-col space-y-2">
                         <div className="flex justify-between items-center border-b border-slate-800/50 pb-2 mb-1">
                           <span className="font-mono text-slate-300">{geo.ipAddress}</span>
                           <span className="text-[10px] text-slate-500">source: {geo.provider}{geo.updatedAt ? ` · ${new Date(geo.updatedAt).toLocaleString()}` : ''}</span>
                         </div>
                         <div className="grid grid-cols-2 gap-2 text-xs">
                           <div className="flex justify-between p-1 bg-slate-900 rounded"><span className="text-slate-500">Country</span><span className="text-slate-300">{geo.country || 'Unavailable'}</span></div>
                           <div className="flex justify-between p-1 bg-slate-900 rounded"><span className="text-slate-500">Region</span><span className="text-slate-300">{geo.region || 'Unavailable'}</span></div>
                           <div className="flex justify-between p-1 bg-slate-900 rounded"><span className="text-slate-500">City (approximate)</span><span className="text-slate-300">{geo.city || 'Unavailable'}</span></div>
                           <div className="flex justify-between p-1 bg-slate-900 rounded"><span className="text-slate-500">ASN</span><span className="text-slate-300">{geo.asn || 'Unavailable'}</span></div>
                           <div className="flex justify-between p-1 bg-slate-900 rounded col-span-2"><span className="text-slate-500">ISP / Organization</span><span className="text-slate-300 truncate pl-2" title={geo.isp ?? undefined}>{geo.isp || 'Unavailable'}</span></div>
                           {geo.latitude != null && geo.longitude != null && (
                             <div className="flex justify-between p-1 bg-slate-900 rounded col-span-2"><span className="text-slate-500">Approximate coordinates</span><span className="text-slate-300">{geo.latitude.toFixed(2)}, {geo.longitude.toFixed(2)}</span></div>
                           )}
                         </div>
                       </div>
                     ))}
                   </div>
                 ) : (
                   <div className="text-sm text-slate-500 text-center py-2">No IP intelligence available for this email's relay hops</div>
                 )}
              </div>
            </div>

            {/* Evidence Graph (Phase I) */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
                <h2 className="font-medium text-slate-200">Evidence Graph</h2>
                <span className="text-xs bg-violet-500/20 text-violet-400 px-2 py-1 rounded border border-violet-500/30">
                  {data.evidenceGraph.metadata.nodeCount} nodes · {data.evidenceGraph.metadata.edgeCount} edges
                  {data.evidenceGraph.metadata.truncated ? ' · truncated' : ''}
                </span>
              </div>
              <div className="p-5">
                <EvidenceGraphView graph={data.evidenceGraph} />
              </div>
            </div>

            {/* Forensic Report Generation (Phase J) */}
            {activeEmailId && <ReportsPanel emailId={activeEmailId} />}

            {/* Evidence & Chain of Custody */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50">
                <h2 className="font-medium text-slate-200">Evidence &amp; Chain of Custody</h2>
              </div>
              <div className="p-5">
                {data.evidence === null || !data.email.caseId ? (
                  <div className="text-sm text-slate-500 text-center py-2">
                    This email is not yet linked to a case, so there is no evidence to show.
                  </div>
                ) : data.evidence.length > 0 ? (
                  <div className="space-y-3">
                    {data.evidence.map((ev) => (
                      <ChainOfCustody key={ev.id} caseId={data.email.caseId as string} evidence={ev} />
                    ))}
                  </div>
                ) : (
                  <div className="text-sm text-slate-500 text-center py-2">No evidence recorded for this case yet.</div>
                )}
              </div>
            </div>

            {/* Forensic Timeline (Case) */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50">
                <h2 className="font-medium text-slate-200">Forensic Timeline (Case Activity)</h2>
              </div>
              <div className="p-5">
                {data.email.caseId ? (
                  <UnifiedForensicTimeline caseId={data.email.caseId} />
                ) : (
                  <div className="text-sm text-slate-500 text-center py-2">
                    This email is not yet linked to a case, so there is no case timeline to show.
                  </div>
                )}
              </div>
            </div>

            {/* Investigation Context */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50">
                <h2 className="font-medium text-slate-200">Investigation Context</h2>
              </div>
              <div className="p-5">
                {data.investigationContext === null ? (
                  <div className="text-sm text-slate-500 text-center py-2">
                    This email is not yet linked to a case.
                  </div>
                ) : (
                  <div className="space-y-4">
                    {data.investigationContext.case && (
                      <div className="bg-slate-950 border border-slate-800 rounded p-3 text-xs space-y-1">
                        <div className="flex justify-between"><span className="text-slate-500">Case ID</span><span className="text-slate-300 font-mono truncate max-w-[220px]" title={data.investigationContext.case.id}>{data.investigationContext.case.id}</span></div>
                        <div className="flex justify-between"><span className="text-slate-500">Case</span><span className="text-slate-200 font-medium">{data.investigationContext.case.title}</span></div>
                        <div className="flex justify-between"><span className="text-slate-500">Status</span><span className="text-slate-300">{data.investigationContext.case.status}</span></div>
                        <div className="flex justify-between"><span className="text-slate-500">Priority</span><span className="text-slate-300">{data.investigationContext.case.priority}</span></div>
                        <div className="flex justify-between"><span className="text-slate-500">Owner/Assignee</span><span className="text-slate-300">{data.investigationContext.case.assignedUserId ?? 'Unassigned'}</span></div>
                        <Link
                          to={`/cases/${data.investigationContext.case.id}`}
                          className="inline-flex items-center gap-1 text-indigo-400 hover:text-indigo-300 pt-1 font-medium"
                        >
                          View Case <ArrowRight className="w-3 h-3" />
                        </Link>
                      </div>
                    )}
                    <div>
                      <h3 className="text-xs font-medium text-slate-400 mb-2">Investigations ({data.investigationContext.investigations.length})</h3>
                      {data.investigationContext.investigations.length > 0 ? (
                        <div className="space-y-2">
                          {data.investigationContext.investigations.map((inv) => (
                            <Link
                              key={inv.id}
                              to={`/cases/${inv.caseId}/investigations/${inv.id}/workspace`}
                              className="block bg-slate-950 border border-slate-800 rounded p-3 text-xs text-slate-300 hover:border-indigo-500/50 transition-colors"
                            >
                              {inv.title}
                            </Link>
                          ))}
                        </div>
                      ) : (
                        <div className="text-xs text-slate-600">No investigations opened for this case yet.</div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>

          </div>

          {/* Right Column: MIME Tree */}
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
              <h2 className="font-medium text-slate-200 mb-4 flex items-center">
                <FileText className="w-5 h-5 mr-2 text-slate-400" />
                MIME Tree
              </h2>
              <div className="space-y-3">
                {data.mimeParts.map((part, i) => (
                  <div key={i} className="p-3 bg-slate-950 border border-slate-800 rounded flex flex-col items-start">
                    <div className="text-sm font-medium text-slate-200 flex items-center w-full justify-between">
                       <span>{part.partIndex}. {part.filename || 'Part'}</span>
                       <span className="text-xs bg-slate-800 px-1.5 py-0.5 rounded text-slate-400">{part.contentType}</span>
                    </div>
                    <div className="text-xs text-slate-500 mt-2">
                       Size: {part.sizeBytes ? Math.round(part.sizeBytes / 1024) + ' KB' : 'Unknown'}
                       {part.isAttachment && <span className="ml-2 text-amber-500 border border-amber-500/20 bg-amber-500/10 px-1 rounded">Attachment</span>}
                    </div>
                  </div>
                ))}
                {data.mimeParts.length === 0 && (
                   <div className="text-sm text-slate-500">No MIME parts detected.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
