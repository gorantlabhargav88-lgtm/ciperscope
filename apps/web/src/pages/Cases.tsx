import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { Loader2, AlertTriangle, Briefcase, ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { PriorityBadge } from '../components/threats/PriorityBadge';
import type { CaseSummary } from '@ciperscope/types';

const STATUS_STYLES: Record<string, string> = {
  OPEN: 'bg-blue-950/30 text-blue-400 border-blue-900/50',
  INVESTIGATING: 'bg-purple-950/30 text-purple-400 border-purple-900/50',
  CONTAINED: 'bg-emerald-950/30 text-emerald-400 border-emerald-900/50',
  RESOLVED: 'bg-slate-800 text-slate-400 border-slate-700',
  CLOSED: 'bg-slate-800 text-slate-500 border-slate-700',
};

export const Cases = () => {
  const [cursor, setCursor] = useState<string | undefined>();

  const { data, isLoading, error } = useQuery({
    queryKey: ['cases', cursor],
    queryFn: () =>
      api.get<{ items: CaseSummary[]; nextCursor?: string }>(
        `/cases?limit=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`
      ),
  });

  return (
    <div className="space-y-6 pb-20">
      <header className="mb-8 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <Briefcase className="w-8 h-8 text-blue-500" />
          <h1 className="text-3xl font-bold text-white tracking-tight">Active Cases</h1>
        </div>
        <p className="text-slate-400 mt-2">Manage and track security incidents across the organization.</p>
      </header>

      {isLoading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 text-blue-500 animate-spin" />
        </div>
      ) : error ? (
        <div className="bg-red-950/30 border border-red-900/50 p-6 rounded-xl flex items-center gap-4">
          <AlertTriangle className="w-8 h-8 text-red-500" />
          <div>
            <h3 className="text-red-200 font-medium">Failed to load cases</h3>
            <p className="text-red-400/80 text-sm">{(error as any)?.message}</p>
          </div>
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/50 text-slate-400 uppercase text-xs border-b border-slate-800">
              <tr>
                <th className="px-6 py-4 font-medium">Case ID</th>
                <th className="px-6 py-4 font-medium">Title</th>
                <th className="px-6 py-4 font-medium">Status</th>
                <th className="px-6 py-4 font-medium">Priority</th>
                <th className="px-6 py-4 font-medium">Created</th>
                <th className="px-6 py-4 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {data?.items?.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-slate-500 italic">
                    No cases found.
                  </td>
                </tr>
              ) : (
                data?.items?.map((c) => (
                  <tr key={c.id} className="hover:bg-slate-800/30 transition-colors group">
                    <td className="px-6 py-4 font-mono text-xs text-slate-500">{c.id.split('-')[0]}</td>
                    <td className="px-6 py-4 font-medium text-slate-200">{c.title}</td>
                    <td className="px-6 py-4">
                      <span className={`px-2.5 py-1 rounded text-xs font-medium border ${STATUS_STYLES[c.status] ?? STATUS_STYLES.CLOSED}`}>
                        {c.status}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <PriorityBadge priority={c.priority} />
                    </td>
                    <td className="px-6 py-4 text-slate-400">{new Date(c.createdAt).toLocaleDateString()}</td>
                    <td className="px-6 py-4 text-right">
                      <Link to={`/cases/${c.id}`} className="text-blue-400 hover:text-blue-300 inline-flex items-center text-xs font-medium transition-colors">
                        View Details <ChevronRight className="w-4 h-4 ml-1" />
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          
          {data?.nextCursor && (
            <div className="p-4 border-t border-slate-800 flex justify-center">
              <button 
                onClick={() => setCursor(data.nextCursor)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm font-medium transition-colors border border-slate-700 hover:border-slate-600"
              >
                Load More
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
