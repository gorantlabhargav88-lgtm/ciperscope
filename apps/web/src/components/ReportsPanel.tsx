import { useCallback, useEffect, useState } from 'react';
import { FileText, Download, Loader2, AlertTriangle, CheckCircle, XCircle, Clock } from 'lucide-react';
import { apiClient } from '../lib/apiClient';
import type { ForensicReport, ForensicReportStatus } from '@ciperscope/types';

const STATUS_STYLES: Record<ForensicReportStatus, string> = {
  QUEUED: 'bg-slate-700/50 text-slate-300 border-slate-600/50',
  GENERATING: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
  COMPLETED: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  FAILED: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
};

const STATUS_ICON: Record<ForensicReportStatus, JSX.Element> = {
  QUEUED: <Clock className="w-3.5 h-3.5" />,
  GENERATING: <Loader2 className="w-3.5 h-3.5 animate-spin" />,
  COMPLETED: <CheckCircle className="w-3.5 h-3.5" />,
  FAILED: <XCircle className="w-3.5 h-3.5" />,
};

/**
 * Reports section for the email investigation page. Never shows a report as
 * existing/ready until the backend confirms it — reports are fetched
 * lazily (only for this emailId) and re-polled only while one is actually
 * QUEUED/GENERATING, never assumed complete client-side.
 */
export function ReportsPanel({ emailId }: { emailId: string }) {
  const [reports, setReports] = useState<ForensicReport[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const loadReports = useCallback(async () => {
    try {
      const res = await apiClient.getEmailReports(emailId);
      setReports(res.reports);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load reports');
    }
  }, [emailId]);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  useEffect(() => {
    const inFlight = reports?.some((r) => r.status === 'QUEUED' || r.status === 'GENERATING');
    if (!inFlight) return;
    const interval = setInterval(loadReports, 2500);
    return () => clearInterval(interval);
  }, [reports, loadReports]);

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    try {
      await apiClient.createEmailReport(emailId);
      await loadReports();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to request report generation');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (reportId: string) => {
    setDownloadingId(reportId);
    setError(null);
    try {
      const blob = await apiClient.downloadReport(reportId);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `ciperscope-report-${reportId}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to download report');
    } finally {
      setDownloadingId(null);
    }
  };

  const hasInFlightReport = reports?.some((r) => r.status === 'QUEUED' || r.status === 'GENERATING') ?? false;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
      <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
        <h2 className="font-medium text-slate-200 flex items-center">
          <FileText className="w-4 h-4 mr-2 text-slate-400" />
          Forensic Reports
        </h2>
        <button
          onClick={handleGenerate}
          disabled={generating || hasInFlightReport}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-1.5 rounded-lg font-medium text-xs flex items-center transition-colors disabled:opacity-50"
        >
          {generating || hasInFlightReport ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <FileText className="w-3.5 h-3.5 mr-1.5" />}
          {hasInFlightReport ? 'Generating…' : 'Generate Report'}
        </button>
      </div>
      <div className="p-5 space-y-3">
        {error && (
          <div className="p-3 text-xs text-rose-400 border border-rose-900/50 bg-rose-950/20 rounded flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {reports === null && !error && (
          <div className="text-xs text-slate-500">Loading reports…</div>
        )}

        {reports !== null && reports.length === 0 && (
          <div className="text-sm text-slate-500 text-center py-2">
            No forensic report has been generated for this email yet.
          </div>
        )}

        {reports !== null && reports.length > 0 && (
          <div className="space-y-2">
            {reports.map((report) => (
              <div key={report.id} className="bg-slate-950 border border-slate-800 rounded p-3 text-xs flex flex-col space-y-2">
                <div className="flex justify-between items-center">
                  <span className={`px-2 py-0.5 rounded font-bold border flex items-center gap-1.5 ${STATUS_STYLES[report.status]}`}>
                    {STATUS_ICON[report.status]}
                    {report.status}
                  </span>
                  <span className="text-slate-500">v{report.reportVersion}</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-slate-400">
                  <div>Requested: <span className="text-slate-300">{new Date(report.createdAt).toLocaleString()}</span></div>
                  <div>Generated: <span className="text-slate-300">{report.generatedAt ? new Date(report.generatedAt).toLocaleString() : 'N/A'}</span></div>
                </div>
                {report.sha256 && (
                  <div className="text-slate-500 font-mono break-all"><span className="text-slate-600 mr-2">SHA-256:</span>{report.sha256}</div>
                )}
                {report.status === 'FAILED' && report.errorMessage && (
                  <div className="text-rose-400 border border-rose-500/30 bg-rose-500/10 px-2 py-1 rounded">
                    {report.errorMessage}
                  </div>
                )}
                {report.status === 'COMPLETED' && (
                  <button
                    onClick={() => handleDownload(report.id)}
                    disabled={downloadingId === report.id}
                    className="self-start bg-slate-800 hover:bg-slate-700 text-slate-200 px-2.5 py-1 rounded font-medium flex items-center transition-colors disabled:opacity-50"
                  >
                    {downloadingId === report.id ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Download className="w-3.5 h-3.5 mr-1.5" />}
                    Download Report
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
