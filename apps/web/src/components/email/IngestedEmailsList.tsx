import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import {
  Inbox,
  Search,
  RefreshCw,
  Paperclip,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  ArrowRight,
  Loader2,
  CheckCircle2,
  XCircle,
  Mail,
  UploadCloud,
} from 'lucide-react';
import { apiClient } from '../../lib/apiClient';
import type { EmailListItem, EmailClassification, AnalysisState } from '@ciperscope/types';

interface IngestedEmailsListProps {
  onSelectEmail?: (emailId: string) => void;
  selectedEmailId?: string | null;
}

const CLASSIFICATION_STYLES: Record<string, string> = {
  PHISHING: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
  MALWARE: 'bg-rose-600/20 text-rose-300 border-rose-600/40',
  BEC: 'bg-red-500/15 text-red-400 border-red-500/30',
  IMPERSONATION: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  FRAUD: 'bg-amber-600/15 text-amber-300 border-amber-600/30',
  SUSPICIOUS: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  LEGITIMATE: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  UNKNOWN: 'bg-slate-700/40 text-slate-400 border-slate-700',
};

const PRIORITY_BADGES: Record<string, string> = {
  P1: 'bg-rose-500/20 text-rose-400 border-rose-500/40 font-bold',
  P2: 'bg-amber-500/20 text-amber-400 border-amber-500/40 font-semibold',
  P3: 'bg-slate-700/50 text-slate-300 border-slate-600/50',
};

export const IngestedEmailsList: React.FC<IngestedEmailsListProps> = ({ onSelectEmail, selectedEmailId }) => {
  const navigate = useNavigate();

  const [page, setPage] = useState(1);
  const [limit] = useState(15);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [classificationFilter, setClassificationFilter] = useState<string>('ALL');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ['ingested-emails', page, limit, search, statusFilter, classificationFilter, sourceFilter],
    queryFn: () =>
      apiClient.getEmails({
        page,
        limit,
        search: search.trim() || undefined,
        status: statusFilter !== 'ALL' ? (statusFilter as AnalysisState) : undefined,
        classification: classificationFilter !== 'ALL' ? (classificationFilter as EmailClassification) : undefined,
        source: sourceFilter !== 'ALL' ? sourceFilter : undefined,
      }),
    refetchInterval: 8000, // Poll every 8s for live incoming emails
    placeholderData: keepPreviousData,
  });

  const handleRowClick = (emailId: string) => {
    if (onSelectEmail) {
      onSelectEmail(emailId);
    } else {
      navigate(`/email-analysis/${emailId}`);
    }
  };

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = data?.totalPages ?? 1;

  // Stats calculation from current page items
  const gmailCount = items.filter((i) => i.ingestionSrc === 'GMAIL').length;
  const threatCount = items.filter((i) => i.isSuspiciousOrMalicious).length;
  const processingCount = items.filter((i) => i.analysisStatus === 'PROCESSING' || i.analysisStatus === 'PENDING').length;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      {/* Header Bar */}
      <div className="p-5 border-b border-slate-800 bg-slate-950/60 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <Inbox className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold text-slate-100">Received / Ingested Emails</h2>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                {total} total
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Real emails synced from Gmail or uploaded for forensic pipeline processing.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Polling Indicator */}
          <div className="flex items-center gap-2 text-xs text-slate-400 px-3 py-1.5 rounded-md bg-slate-800/40 border border-slate-800">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="hidden sm:inline">Live Stream Active</span>
          </div>

          {/* Refresh Button */}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition-colors disabled:opacity-50"
            title="Refresh email list"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin text-indigo-400' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Metrics Bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 p-4 border-b border-slate-800/60 bg-slate-900/40 text-xs">
        <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
          <div className="text-slate-400">Total in View</div>
          <div className="text-base font-semibold text-slate-200 mt-0.5">{total}</div>
        </div>
        <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
          <div className="text-slate-400">Gmail Ingested</div>
          <div className="text-base font-semibold text-emerald-400 mt-0.5">{gmailCount}</div>
        </div>
        <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
          <div className="text-slate-400">Threats / Suspicious</div>
          <div className="text-base font-semibold text-rose-400 mt-0.5">{threatCount}</div>
        </div>
        <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
          <div className="text-slate-400">Pending / Processing</div>
          <div className="text-base font-semibold text-amber-400 mt-0.5">{processingCount}</div>
        </div>
      </div>

      {/* Search and Filters Bar */}
      <div className="p-4 border-b border-slate-800 bg-slate-900/60 flex flex-wrap items-center gap-3">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[220px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            placeholder="Search sender, recipient, subject..."
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
          />
        </div>

        {/* Source Filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-slate-400">Source:</span>
          <select
            value={sourceFilter}
            onChange={(e) => {
              setSourceFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Sources</option>
            <option value="GMAIL">Gmail Synced</option>
            <option value="UPLOAD">Manual Upload</option>
          </select>
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-slate-400">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="COMPLETED">Completed</option>
            <option value="PROCESSING">Processing</option>
            <option value="PENDING">Pending</option>
            <option value="FAILED">Failed</option>
          </select>
        </div>

        {/* Classification Filter */}
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-slate-400">Classification:</span>
          <select
            value={classificationFilter}
            onChange={(e) => {
              setClassificationFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Classifications</option>
            <option value="PHISHING">Phishing</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="MALWARE">Malware</option>
            <option value="BEC">BEC</option>
            <option value="IMPERSONATION">Impersonation</option>
            <option value="FRAUD">Fraud</option>
            <option value="LEGITIMATE">Legitimate</option>
            <option value="UNKNOWN">Unknown</option>
          </select>
        </div>
      </div>

      {/* Main Table / Content */}
      <div className="overflow-x-auto min-h-[320px]">
        {isLoading ? (
          <div className="p-16 flex flex-col items-center justify-center text-slate-400">
            <Loader2 className="w-8 h-8 animate-spin text-indigo-500 mb-3" />
            <p className="text-sm">Loading ingested emails from database...</p>
          </div>
        ) : error ? (
          <div className="p-12 text-center">
            <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto mb-2" />
            <p className="text-sm text-rose-300">
              {error instanceof Error ? error.message : 'Failed to load ingested emails'}
            </p>
            <button
              onClick={() => refetch()}
              className="mt-3 px-3 py-1.5 rounded-lg bg-slate-800 text-xs text-slate-200 border border-slate-700 hover:bg-slate-700"
            >
              Try Again
            </button>
          </div>
        ) : items.length === 0 ? (
          <div className="p-16 text-center text-slate-500">
            <Inbox className="w-10 h-10 mx-auto mb-3 opacity-40 text-slate-400" />
            <p className="text-sm font-medium text-slate-400">No emails found</p>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              {search || statusFilter !== 'ALL' || classificationFilter !== 'ALL' || sourceFilter !== 'ALL'
                ? 'No ingested emails match your filter criteria. Try adjusting your filters or search terms.'
                : 'No emails have been ingested yet. Send an email to your connected Gmail inbox or upload an .eml file to start analysis.'}
            </p>
          </div>
        ) : (
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/40 text-slate-400 font-medium uppercase tracking-wider">
                <th className="py-3 px-4 w-12 text-center">Threat</th>
                <th className="py-3 px-4 w-28">Source</th>
                <th className="py-3 px-4">Subject</th>
                <th className="py-3 px-4">Sender / Recipient</th>
                <th className="py-3 px-4 w-40">Date / Time</th>
                <th className="py-3 px-4 w-32">Status</th>
                <th className="py-3 px-4 w-36">Classification</th>
                <th className="py-3 px-4 w-24 text-center">Priority</th>
                <th className="py-3 px-4 w-24 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {items.map((item: EmailListItem) => {
                const isSelected = selectedEmailId === item.id;
                const formattedDate = item.date
                  ? new Date(item.date).toLocaleString(undefined, {
                      month: 'short',
                      day: 'numeric',
                      year: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                    })
                  : 'N/A';

                return (
                  <tr
                    key={item.id}
                    onClick={() => handleRowClick(item.id)}
                    className={`cursor-pointer transition-colors group ${
                      isSelected
                        ? 'bg-indigo-950/40 hover:bg-indigo-950/60 border-l-2 border-indigo-500'
                        : item.isSuspiciousOrMalicious
                        ? 'hover:bg-rose-950/10'
                        : 'hover:bg-slate-800/40'
                    }`}
                  >
                    {/* Threat Indicator */}
                    <td className="py-3.5 px-4 text-center">
                      {item.isSuspiciousOrMalicious ? (
                        <div
                          className="inline-flex p-1 rounded-md bg-rose-500/15 text-rose-400 border border-rose-500/30"
                          title="Malicious / Suspicious threat indicator detected"
                        >
                          <ShieldAlert className="w-4 h-4" />
                        </div>
                      ) : item.analysisStatus === 'COMPLETED' ? (
                        <div
                          className="inline-flex p-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          title="Analysis complete - no high-severity threat flag"
                        >
                          <ShieldCheck className="w-4 h-4" />
                        </div>
                      ) : (
                        <div className="inline-flex p-1 rounded-md bg-slate-800 text-slate-500">
                          <Clock className="w-4 h-4" />
                        </div>
                      )}
                    </td>

                    {/* Source */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {item.ingestionSrc === 'GMAIL' ? (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-red-500/10 text-red-300 border border-red-500/20">
                          <Mail className="w-3 h-3 text-red-400" />
                          Gmail
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-300 border border-slate-700">
                          <UploadCloud className="w-3 h-3 text-slate-400" />
                          Upload
                        </span>
                      )}
                    </td>

                    {/* Subject */}
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2 max-w-md">
                        <span className="font-medium text-slate-200 truncate group-hover:text-indigo-300 transition-colors">
                          {item.subject || '(No Subject)'}
                        </span>
                        {item.attachmentCount > 0 && (
                          <span
                            className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 text-[10px] shrink-0"
                            title={`${item.attachmentCount} attachment(s)`}
                          >
                            <Paperclip className="w-2.5 h-2.5" />
                            {item.attachmentCount}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Sender & Recipient */}
                    <td className="py-3.5 px-4">
                      <div className="flex flex-col gap-0.5 max-w-xs">
                        <div className="truncate text-slate-300 font-mono text-[11px]" title={`From: ${item.sender}`}>
                          <span className="text-slate-500 mr-1 font-sans">From:</span>
                          {item.sender || 'Unknown'}
                        </div>
                        <div className="truncate text-slate-400 font-mono text-[11px]" title={`To: ${item.recipient}`}>
                          <span className="text-slate-500 mr-1 font-sans">To:</span>
                          {item.recipient || 'Unknown'}
                        </div>
                      </div>
                    </td>

                    {/* Received Date/Time */}
                    <td className="py-3.5 px-4 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                      {formattedDate}
                    </td>

                    {/* Analysis Status */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {item.analysisStatus === 'COMPLETED' ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Completed
                        </span>
                      ) : item.analysisStatus === 'PROCESSING' ? (
                        <span className="inline-flex items-center gap-1 text-indigo-400 font-medium">
                          <Loader2 className="w-3.5 h-3.5 animate-spin" />
                          Processing
                        </span>
                      ) : item.analysisStatus === 'PENDING' ? (
                        <span className="inline-flex items-center gap-1 text-amber-400 font-medium">
                          <Clock className="w-3.5 h-3.5" />
                          Pending
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-rose-400 font-medium">
                          <XCircle className="w-3.5 h-3.5" />
                          Failed
                        </span>
                      )}
                    </td>

                    {/* Classification & Risk Score */}
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                            CLASSIFICATION_STYLES[item.classification] || CLASSIFICATION_STYLES.UNKNOWN
                          }`}
                        >
                          {item.classification}
                        </span>
                        {item.riskScore != null && (
                          <span className="text-[11px] text-slate-400 font-mono">
                            {Math.round(item.riskScore)}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Priority */}
                    <td className="py-3.5 px-4 text-center whitespace-nowrap">
                      {item.priority ? (
                        <span
                          className={`px-2 py-0.5 rounded text-[11px] border ${
                            PRIORITY_BADGES[item.priority] || 'bg-slate-800 text-slate-400 border-slate-700'
                          }`}
                        >
                          {item.priority}
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>

                    {/* Action */}
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRowClick(item.id);
                        }}
                        className="inline-flex items-center gap-1 text-indigo-400 hover:text-indigo-300 font-medium transition-colors"
                      >
                        <span>Analyze</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination Bar */}
      {totalPages > 1 && (
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing {(page - 1) * limit + 1} to {Math.min(page * limit, total)} of {total} emails
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 border border-slate-700 font-medium transition-colors"
            >
              Previous
            </button>
            <span className="px-2 text-slate-300">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 border border-slate-700 font-medium transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
