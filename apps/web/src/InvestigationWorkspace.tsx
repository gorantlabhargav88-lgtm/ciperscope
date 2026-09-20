import React, { useCallback, useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient, ApiError } from './lib/apiClient';
import { ChainOfCustody } from './components/evidence/ChainOfCustody';
import { UnifiedForensicTimeline } from './components/timeline/UnifiedForensicTimeline';
import type { InvestigationIntelligence, AnalystDecision, AnalystDecisionType, Evidence } from '@ciperscope/types';

const DECISION_ACTIONS: { label: string; decision: AnalystDecisionType; className: string }[] = [
  { label: 'Review', decision: 'REVIEWED', className: 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700' },
  { label: 'Confirm Threat', decision: 'CONFIRMED', className: 'bg-rose-600 hover:bg-rose-500 text-white' },
  { label: 'Escalate', decision: 'ESCALATED', className: 'bg-amber-600 hover:bg-amber-500 text-white' },
  { label: 'Dismiss', decision: 'DISMISSED', className: 'bg-slate-800 hover:bg-slate-700 text-slate-400 border border-slate-700' },
];

export const InvestigationWorkspace: React.FC = () => {
  const { caseId, investigationId } = useParams();
  const [data, setData] = useState<InvestigationIntelligence | null>(null);
  const [decisions, setDecisions] = useState<AnalystDecision[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [submittingKey, setSubmittingKey] = useState<string | null>(null);
  const [decisionError, setDecisionError] = useState<string | null>(null);

  const loadDecisions = useCallback(async () => {
    if (!caseId || !investigationId) return;
    const res = await apiClient.getInvestigationDecisions(caseId, investigationId);
    setDecisions(res.items);
  }, [caseId, investigationId]);

  useEffect(() => {
    if (!caseId || !investigationId) return;
    let cancelled = false;

    Promise.all([
      apiClient.getInvestigationIntelligence(caseId, investigationId),
      apiClient.getInvestigationDecisions(caseId, investigationId).catch(() => ({ items: [] as AnalystDecision[] })),
      apiClient.getCaseEvidenceList(caseId).catch(() => ({ items: [] as Evidence[], nextCursor: null })),
    ])
      .then(([intelligence, decisionsRes, evidenceRes]) => {
        if (cancelled) return;
        setData(intelligence);
        setDecisions(decisionsRes.items);
        setEvidence(evidenceRes.items);
        setLoading(false);
      })
      .catch((e) => {
        if (cancelled) return;
        setLoadError(e instanceof ApiError ? e.message : 'Failed to load investigation workspace');
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [caseId, investigationId]);

  const handleDecision = async (corr: InvestigationIntelligence['correlations'][number], key: string, decision: AnalystDecisionType) => {
    if (!caseId || !investigationId) return;
    setSubmittingKey(key);
    setDecisionError(null);
    try {
      await apiClient.recordAnalystDecision(caseId, investigationId, {
        targetId: corr.targetId,
        targetType: corr.type,
        decision,
      });
      await loadDecisions();
    } catch (e) {
      setDecisionError(e instanceof ApiError ? e.message : 'Failed to record analyst decision');
    } finally {
      setSubmittingKey(null);
    }
  };

  if (loading) return <div className="p-8 text-center text-gray-500 text-lg">Loading SOC Workspace...</div>;
  if (loadError) return <div className="p-8 text-center text-red-500">{loadError}</div>;
  if (!data) return <div className="p-8 text-center text-red-500">Failed to load intelligence data.</div>;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 p-8 font-sans">
      <header className="mb-8 border-b border-slate-800 pb-4">
        <h1 className="text-3xl font-bold text-white tracking-tight">Investigation Workspace</h1>
        <p className="text-slate-400 mt-2">Case: {caseId} | Investigation: {investigationId}</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-lg hover:border-blue-500 transition-colors">
          <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-2">Max Risk Score</h3>
          <p className={`text-4xl font-bold ${data.riskSummary.maximumRiskScore > 80 ? 'text-red-500' : 'text-emerald-400'}`}>
            {data.riskSummary.maximumRiskScore.toFixed(1)}
          </p>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-lg hover:border-blue-500 transition-colors">
          <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-2">High Risk Entities</h3>
          <p className="text-4xl font-bold text-orange-400">{data.riskSummary.highRiskCount}</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-lg hover:border-blue-500 transition-colors">
          <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-2">Correlations</h3>
          <p className="text-4xl font-bold text-blue-400">{data.correlations.length}</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-lg hover:border-blue-500 transition-colors">
          <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-2">Total Evidence</h3>
          <p className="text-4xl font-bold text-purple-400">{data.riskSummary.entityCounts.evidence}</p>
        </div>
      </div>

      {decisionError && (
        <div className="mb-6 p-3 rounded-lg border border-rose-900/50 bg-rose-950/20 text-sm text-rose-400">{decisionError}</div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="space-y-6">
          <h2 className="text-xl font-semibold text-white mb-4 border-b border-slate-800 pb-2">Attention Indicators</h2>
          {data.attentionIndicators.length === 0 ? (
            <p className="text-slate-500 italic">No active attention indicators.</p>
          ) : (
            data.attentionIndicators.map((ai, idx) => (
              <div key={idx} className={`p-4 rounded-lg border ${ai.severity === 'CRITICAL' ? 'bg-red-950/30 border-red-900/50 text-red-200' : ai.severity === 'HIGH' ? 'bg-orange-950/30 border-orange-900/50 text-orange-200' : 'bg-blue-950/30 border-blue-900/50 text-blue-200'}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-sm tracking-wide uppercase">{ai.type}</span>
                  <span className="text-xs font-mono px-2 py-1 bg-black/30 rounded">{ai.severity}</span>
                </div>
                <p className="text-sm opacity-90">{ai.message}</p>
              </div>
            ))
          )}

          <h2 className="text-xl font-semibold text-white mb-4 mt-8 border-b border-slate-800 pb-2">Evidence &amp; Chain of Custody ({evidence.length})</h2>
          {evidence.length === 0 ? (
            <p className="text-slate-500 italic">No evidence recorded for this case yet.</p>
          ) : (
            <div className="space-y-2">
              {caseId && evidence.map((ev) => <ChainOfCustody key={ev.id} caseId={caseId} evidence={ev} />)}
            </div>
          )}
        </div>

        <div className="space-y-6">
          <h2 className="text-xl font-semibold text-white mb-4 border-b border-slate-800 pb-2">Top Correlations</h2>
          {data.correlations.length === 0 ? (
            <p className="text-slate-500 italic">No correlations found.</p>
          ) : (
            <div className="space-y-4">
              {data.correlations.slice(0, 5).map((corr, idx) => {
                const key = `${corr.type}:${corr.sourceId}:${corr.targetId}`;
                return (
                  <div key={idx} className="bg-slate-900 border border-slate-800 p-4 rounded-lg flex flex-col hover:bg-slate-800/50 transition-colors">
                    <div className="flex justify-between items-start mb-2">
                      <span className="text-sm font-semibold text-indigo-400 bg-indigo-950/50 px-2 py-1 rounded">{corr.type}</span>
                      <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2 py-1 rounded border border-slate-800">Confidence: {(corr.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <ul className="text-sm text-slate-300 list-disc list-inside mt-2 space-y-1">
                      {corr.reasons.map((r: string, ridx: number) => (
                        <li key={ridx}>{r}</li>
                      ))}
                    </ul>
                    <div className="mt-4 pt-3 border-t border-slate-800/50 flex flex-wrap gap-2">
                      {DECISION_ACTIONS.map((action) => (
                        <button
                          key={action.decision}
                          disabled={submittingKey === key}
                          onClick={() => handleDecision(corr, key, action.decision)}
                          className={`text-xs px-3 py-1.5 rounded transition-colors disabled:opacity-40 disabled:cursor-wait ${action.className}`}
                        >
                          {submittingKey === key ? 'Saving…' : action.label}
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      <div className="mt-8">
        <h2 className="text-xl font-semibold text-white mb-4 border-b border-slate-800 pb-2">Analyst Decisions</h2>
        {decisions.length === 0 ? (
          <p className="text-slate-500 italic">No analyst decisions recorded for this investigation yet.</p>
        ) : (
          <div className="space-y-3">
            {decisions.map((d, idx) => (
              <div key={d.id ?? idx} className="bg-slate-900 border border-slate-800 p-4 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-sm font-semibold text-slate-200">{d.decision}</span>
                  <span className="text-xs text-slate-500 ml-2">{d.targetType}: {d.targetId}</span>
                  {d.reason && <p className="text-xs text-slate-400 mt-1">{d.reason}</p>}
                </div>
                {d.createdAt && <span className="text-xs text-slate-500">{new Date(d.createdAt).toLocaleString()}</span>}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="mt-8">
        <h2 className="text-xl font-semibold text-white mb-4 border-b border-slate-800 pb-2">Forensic Timeline</h2>
        {caseId && <UnifiedForensicTimeline caseId={caseId} />}
      </div>
    </div>
  );
};
