import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search } from 'lucide-react';
import { Dialog, DialogContent } from './ui/dialog';
import { useCommandPalette } from './command-palette/CommandPaletteContext';
import { ALL_NAV_ITEMS } from '../config/navigation';

export const CommandPalette = () => {
  const { open, setOpen } = useCommandPalette();
  const [query, setQuery] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen(!open);
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [open, setOpen]);

  const handleOpenChange = (next: boolean) => {
    setOpen(next);
    if (!next) setQuery('');
  };

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return ALL_NAV_ITEMS;
    return ALL_NAV_ITEMS.filter((item) => item.label.toLowerCase().includes(q));
  }, [query]);

  const go = (to: string) => {
    setOpen(false);
    navigate(to);
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent hideClose className="p-0 overflow-hidden">
        <div className="flex items-center px-4 py-3 border-b border-border">
          <Search className="w-5 h-5 text-muted-foreground mr-3 shrink-0" />
          <input
            autoFocus
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Go to a page..."
            className="w-full bg-transparent text-foreground focus:outline-none placeholder:text-muted-foreground"
          />
          <kbd className="hidden sm:inline-flex px-2 py-0.5 text-xs text-muted-foreground bg-secondary rounded">ESC</kbd>
        </div>
        <div className="p-2 max-h-96 overflow-y-auto">
          <div className="px-3 py-2 text-xs font-semibold text-muted-foreground">PAGES</div>
          {results.length === 0 && (
            <div className="px-3 py-6 text-sm text-muted-foreground text-center">No matching pages.</div>
          )}
          {results.map((item) => (
            <button
              key={item.to}
              onClick={() => go(item.to)}
              className="w-full text-left px-3 py-2 text-sm text-foreground/90 hover:bg-accent hover:text-accent-foreground rounded-md flex items-center"
            >
              <item.icon className="w-4 h-4 mr-3 text-muted-foreground" />
              {item.label}
            </button>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
};
