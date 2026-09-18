import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';

interface IntelligenceData {
  investigation: any;
  riskSummary: {
    maximumRiskScore: number;
    averageRiskScore: number;
    highRiskCount: number;
    entityCounts: { emails: number, evidence: number, alerts: number, reports: number };
  };
  correlations: any[];
  attentionIndicators: any[];
}

export const InvestigationWorkspace: React.FC = () => {
  const { caseId, investigationId } = useParams();
  const [data, setData] = useState<IntelligenceData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // In a real app, this would use an axios client with authentication
    fetch(`/api/v1/cases/${caseId}/investigations/${investigationId}/intelligence`, {
      headers: { 'x-organization-id': 'org-123' } // Mock tenant ID for demo
    })
      .then(res => res.json())
      .then(d => {
        setData(d);
        setLoading(false);
      })
      .catch(e => {
        console.error(e);
        setLoading(false);
      });
  }, [caseId, investigationId]);

  if (loading) return <div className="p-8 text-center text-gray-500 text-lg">Loading SOC Workspace...</div>;
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
          <p className={`text-4xl font-bold ${data.riskSummary.maximumRiskScore > 0.8 ? 'text-red-500' : 'text-emerald-400'}`}>
            {(data.riskSummary.maximumRiskScore * 100).toFixed(1)}
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
        </div>

        <div className="space-y-6">
          <h2 className="text-xl font-semibold text-white mb-4 border-b border-slate-800 pb-2">Top Correlations</h2>
          {data.correlations.length === 0 ? (
            <p className="text-slate-500 italic">No correlations found.</p>
          ) : (
            <div className="space-y-4">
              {data.correlations.slice(0, 5).map((corr, idx) => (
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
                  <div className="mt-4 pt-3 border-t border-slate-800/50 flex space-x-2">
                    <button className="text-xs bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded transition-colors">Investigate</button>
                    <button className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded transition-colors border border-slate-700">Dismiss</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
