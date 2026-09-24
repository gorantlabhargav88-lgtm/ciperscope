import { Bell, Search, User } from 'lucide-react';
import { useAuth } from '../features/auth/AuthContext';
import { useCommandPalette } from '../components/command-palette/CommandPaletteContext';
import { Tooltip, TooltipTrigger, TooltipContent } from '../components/ui/tooltip';

export const Header = () => {
  const { user, logout } = useAuth();
  const { setOpen } = useCommandPalette();

  return (
    <header className="h-16 border-b border-border bg-background/50 backdrop-blur flex items-center justify-between px-6 sticky top-0 z-10">

      <div className="flex items-center space-x-4 flex-1">
        <button
          onClick={() => setOpen(true)}
          className="flex items-center text-muted-foreground bg-card border border-border rounded-md px-3 py-1.5 text-sm w-64 hover:bg-accent/50 transition-colors"
        >
          <Search className="w-4 h-4 mr-2" />
          <span>Search pages... (Ctrl+K)</span>
        </button>
      </div>

      <div className="flex items-center space-x-4">
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              disabled
              aria-label="Notifications (coming soon)"
              className="text-muted-foreground/50 cursor-not-allowed"
            >
              <Bell className="w-5 h-5" />
            </button>
          </TooltipTrigger>
          <TooltipContent>Notifications — coming soon, no live event source yet</TooltipContent>
        </Tooltip>
        <div className="h-5 w-px bg-border mx-2" />
        <div className="flex items-center space-x-3">
          <div className="text-right hidden sm:block">
            <div className="text-sm font-medium text-foreground">{user?.name}</div>
            <div className="text-xs text-muted-foreground">{user?.role}</div>
          </div>
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                onClick={logout}
                aria-label="Log out"
                className="w-8 h-8 rounded-full bg-secondary flex items-center justify-center text-foreground/80 hover:bg-accent transition-colors"
              >
                <User className="w-4 h-4" />
              </button>
            </TooltipTrigger>
            <TooltipContent>Log out</TooltipContent>
          </Tooltip>
        </div>
      </div>
    </header>
  );
};
