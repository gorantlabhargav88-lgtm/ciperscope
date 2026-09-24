import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { FileText, Plus, Trash2, Loader2, ChevronDown, ChevronRight } from 'lucide-react';
import { apiClient } from '../../lib/apiClient';
import { classifyApiError } from '../../lib/apiErrorState';

/**
 * Case-scoped narrative reports (GET/POST/DELETE /cases/:caseId/reports*) —
 * distinct from the email-centric generated PDF ForensicReport handled by
 * ReportsPanel.tsx. `contentHtml` is always rendered as plain text here
 * (never dangerouslySetInnerHTML) since nothing sanitizes it server-side.
 */
export function CaseReports({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ['case-reports', caseId],
    queryFn: () => apiClient.getCaseReports(caseId),
  });

  const createMutation = useMutation({
    mutationFn: () => apiClient.createCaseReport(caseId, { title, contentHtml: content || undefined }),
    onSuccess: () => {
      setTitle('');
      setContent('');
      setShowCreate(false);
      queryClient.invalidateQueries({ queryKey: ['case-reports', caseId] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (reportId: string) => apiClient.deleteCaseReport(caseId, reportId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['case-reports', caseId] }),
  });

  const classified = error ? classifyApiError(error, "case's reports") : null;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs text-slate-500">Analyst-authored notes attached to this case.</p>
        <button
          onClick={() => setShowCreate((v) => !v)}
          className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 font-medium"
        >
          <Plus className="w-3.5 h-3.5" /> New Report
        </button>
      </div>

      {showCreate && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Report title"
            className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-600"
          />
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Report content (plain text)"
            rows={4}
            className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-blue-600 resize-y"
          />
          <button
            onClick={() => createMutation.mutate()}
            disabled={!title || createMutation.isPending}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded text-xs font-medium transition-colors"
          >
            {createMutation.isPending && <Loader2 className="w-3.5 h-3.5 animate-spin" />} Save Report
          </button>
        </div>
      )}

      {isLoading ? (
        <div className="flex justify-center py-6"><Loader2 className="w-5 h-5 text-blue-500 animate-spin" /></div>
      ) : classified ? (
        <p className="text-xs text-red-400">{classified.message}</p>
      ) : data?.items.length === 0 ? (
        <p className="text-slate-500 italic text-sm">No reports written for this case yet.</p>
      ) : (
        <div className="space-y-2">
          {data?.items.map((r) => (
            <div key={r.id} className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <button
                onClick={() => setExpandedId(expandedId === r.id ? null : r.id)}
                className="w-full flex items-center justify-between px-3 py-2.5 text-left hover:bg-slate-800/40 transition-colors"
              >
                <span className="flex items-center gap-2 min-w-0">
                  <FileText className="w-4 h-4 text-slate-500 shrink-0" />
                  <span className="text-sm text-slate-200 truncate">{r.title}</span>
                </span>
                <span className="flex items-center gap-3 shrink-0">
                  <span className="text-xs text-slate-600">{new Date(r.createdAt).toLocaleDateString()}</span>
                  {expandedId === r.id ? <ChevronDown className="w-3.5 h-3.5 text-slate-500" /> : <ChevronRight className="w-3.5 h-3.5 text-slate-500" />}
                </span>
              </button>
              {expandedId === r.id && (
                <div className="px-3 pb-3 border-t border-slate-800 pt-2">
                  <p className="text-sm text-slate-300 whitespace-pre-wrap break-words">{r.contentHtml || <span className="italic text-slate-600">No content.</span>}</p>
                  <button
                    onClick={() => deleteMutation.mutate(r.id)}
                    disabled={deleteMutation.isPending}
                    className="mt-2 inline-flex items-center gap-1 text-xs text-red-400 hover:text-red-300"
                  >
                    <Trash2 className="w-3 h-3" /> Delete
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
