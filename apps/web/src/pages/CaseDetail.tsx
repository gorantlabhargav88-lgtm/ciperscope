import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Loader2, AlertTriangle, Briefcase, ChevronRight, FileText } from 'lucide-react';
import { apiClient, ApiError } from '../lib/apiClient';
import { SeverityBadge } from '../components/threats/SeverityBadge';
import { PriorityBadge } from '../components/threats/PriorityBadge';
import { ChainOfCustody } from '../components/evidence/ChainOfCustody';
import { UnifiedForensicTimeline } from '../components/timeline/UnifiedForensicTimeline';
import { CaseReports } from '../components/case/CaseReports';
import { CaseHistory } from '../components/case/CaseHistory';
import type { CaseSummary, InvestigationSummary, Evidence } from '@ciperscope/types';

const STATUS_STYLES: Record<string, string> = {
  OPEN: 'bg-blue-950/30 text-blue-400 border-blue-900/50',
  INVESTIGATING: 'bg-purple-950/30 text-purple-400 border-purple-900/50',
  CONTAINED: 'bg-emerald-950/30 text-emerald-400 border-emerald-900/50',
  RESOLVED: 'bg-slate-800 text-slate-400 border-slate-700',
  CLOSED: 'bg-slate-800 text-slate-500 border-slate-700',
};

/**
 * Real case detail page — closes the dead-link gap where Cases.tsx and
 * Alerts.tsx both linked to `/cases/:caseId` with no matching route (it
 * silently fell through to the wildcard redirect to "/"). Also the only
 * place in the app a user can discover a case's investigations and reach
 * the real deep-linked InvestigationWorkspace without already knowing
 * both a caseId and investigationId.
 */
export const CaseDetail = () => {
  const { caseId } = useParams<{ caseId: string }>();
  const [caseData, setCaseData] = useState<CaseSummary | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationSummary[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!caseId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      apiClient.getCase(caseId),
      apiClient.getCaseInvestigations(caseId).catch(() => ({ items: [] as InvestigationSummary[] })),
      apiClient.getCaseEvidenceList(caseId).catch(() => ({ items: [] as Evidence[], nextCursor: null })),
    ])
      .then(([caseRes, investigationsRes, evidenceRes]) => {
        if (cancelled) return;
        setCaseData(caseRes);
        setInvestigations(investigationsRes.items);
        setEvidence(evidenceRes.items);
        setLoading(false);
      })
      .catch((e) => {
        if (cancelled) return;
        setError(e instanceof ApiError ? e.message : 'Failed to load case');
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [caseId]);

  if (loading) {
    return (
      <div className="flex justify-center items-center py-20">
        <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
      </div>
    );
  }

  if (error || !caseData) {
    return (
      <div className="bg-red-950/30 border border-red-900/50 p-6 rounded-xl flex items-center gap-4">
        <AlertTriangle className="w-8 h-8 text-red-500" />
        <div>
          <h3 className="text-red-200 font-medium">Failed to load case</h3>
          <p className="text-red-400/80 text-sm">{error ?? 'Case not found, or you do not have access to it.'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 pb-20">
      <header className="border-b border-slate-800 pb-4">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <Briefcase className="w-8 h-8 text-blue-500 shrink-0" />
            <div>
              <h1 className="text-3xl font-bold text-white tracking-tight">{caseData.title}</h1>
              <p className="text-slate-500 text-xs font-mono mt-1">{caseData.id}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className={`px-2.5 py-1 rounded text-xs font-medium border ${STATUS_STYLES[caseData.status] ?? STATUS_STYLES.CLOSED}`}>
              {caseData.status}
            </span>
            <PriorityBadge priority={caseData.priority} />
            {caseData.severity && <SeverityBadge level={caseData.severity} />}
          </div>
        </div>
        {caseData.description && <p className="text-slate-400 mt-3 max-w-3xl">{caseData.description}</p>}
        <dl className="mt-4 flex flex-wrap gap-x-8 gap-y-2 text-xs text-slate-500">
          <div><dt className="inline text-slate-600">Created </dt><dd className="inline">{new Date(caseData.createdAt).toLocaleString()}</dd></div>
          <div><dt className="inline text-slate-600">Updated </dt><dd className="inline">{new Date(caseData.updatedAt).toLocaleString()}</dd></div>
          {caseData.resolvedAt && <div><dt className="inline text-slate-600">Resolved </dt><dd className="inline">{new Date(caseData.resolvedAt).toLocaleString()}</dd></div>}
        </dl>
      </header>

      <section>
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
          Investigations <span className="text-sm font-normal text-slate-500">({investigations.length})</span>
        </h2>
        {investigations.length === 0 ? (
          <p className="text-slate-500 italic text-sm">No investigations opened for this case yet.</p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {investigations.map((inv) => (
              <Link
                key={inv.id}
                to={`/cases/${caseId}/investigations/${inv.id}/workspace`}
                className="bg-slate-900 border border-slate-800 rounded-xl p-4 hover:border-blue-700/60 hover:bg-slate-800/40 transition-colors flex items-start justify-between gap-3"
              >
                <div className="min-w-0">
                  <p className="font-medium text-slate-200 truncate">{inv.title}</p>
                  {inv.description && <p className="text-xs text-slate-500 mt-1 line-clamp-2">{inv.description}</p>}
                  <p className="text-xs text-slate-600 mt-2">Opened {new Date(inv.createdAt).toLocaleDateString()}</p>
                </div>
                <ChevronRight className="w-4 h-4 text-slate-600 shrink-0 mt-1" />
              </Link>
            ))}
          </div>
        )}
      </section>

      <section>
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
          <FileText className="w-5 h-5 text-slate-500" />
          Evidence &amp; Chain of Custody <span className="text-sm font-normal text-slate-500">({evidence.length})</span>
        </h2>
        {evidence.length === 0 ? (
          <p className="text-slate-500 italic text-sm">No evidence recorded for this case yet.</p>
        ) : (
          <div className="space-y-2">
            {caseId && evidence.map((ev) => <ChainOfCustody key={ev.id} caseId={caseId} evidence={ev} />)}
          </div>
        )}
      </section>

      <section>
        <h2 className="text-xl font-semibold text-white mb-4">Forensic Timeline</h2>
        {caseId && <UnifiedForensicTimeline caseId={caseId} />}
      </section>

      <section>
        <h2 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
          <FileText className="w-5 h-5 text-slate-500" />
          Reports
        </h2>
        {caseId && <CaseReports caseId={caseId} />}
      </section>

      <section>
        <h2 className="text-xl font-semibold text-white mb-4">Change History</h2>
        {caseId && <CaseHistory caseId={caseId} />}
      </section>
    </div>
  );
};
