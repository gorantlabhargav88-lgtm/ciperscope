import { useEffect, useState } from 'react';
import { Search } from 'lucide-react';

export const CommandPalette = () => {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-start justify-center pt-32">
      <div className="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl overflow-hidden">
        <div className="flex items-center px-4 py-3 border-b border-slate-800">
          <Search className="w-5 h-5 text-slate-500 mr-3" />
          <input 
            autoFocus
            type="text" 
            placeholder="Search alerts, cases, IPs, domains..." 
            className="w-full bg-transparent text-slate-100 focus:outline-none placeholder:text-slate-500"
          />
          <kbd className="hidden sm:inline-flex px-2 py-0.5 text-xs text-slate-500 bg-slate-800 rounded">ESC</kbd>
        </div>
        <div className="p-2 max-h-96 overflow-y-auto">
          <div className="px-3 py-2 text-xs font-semibold text-slate-500">SUGGESTIONS</div>
          <button className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-white rounded-md flex items-center">
            <span className="bg-slate-800 p-1 rounded mr-3">/</span> Go to Dashboard
          </button>
          <button className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-white rounded-md flex items-center">
            <span className="bg-slate-800 p-1 rounded mr-3">/</span> View Active Threats
          </button>
        </div>
      </div>
    </div>
  );
};
