import { Bell, Search, User } from 'lucide-react';
import { useAuth } from '../features/auth/AuthContext';

export const Header = () => {
  const { user, logout } = useAuth();

  return (
    <header className="h-16 border-b border-slate-800 bg-slate-950/50 backdrop-blur flex items-center justify-between px-6 sticky top-0 z-10">
      
      <div className="flex items-center space-x-4 flex-1">
        <button className="flex items-center text-slate-400 bg-slate-900 border border-slate-800 rounded-md px-3 py-1.5 text-sm w-64 hover:bg-slate-800 transition-colors">
          <Search className="w-4 h-4 mr-2" />
          <span>Search... (Ctrl+K)</span>
        </button>
      </div>

      <div className="flex items-center space-x-4">
        <button className="text-slate-400 hover:text-slate-200 transition-colors">
          <Bell className="w-5 h-5" />
        </button>
        <div className="h-5 w-px bg-slate-800 mx-2"></div>
        <div className="flex items-center space-x-3">
          <div className="text-right hidden sm:block">
            <div className="text-sm font-medium text-slate-200">{user?.name}</div>
            <div className="text-xs text-slate-500">{user?.role}</div>
          </div>
          <button 
            onClick={logout}
            className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center text-slate-300 hover:bg-slate-700 transition-colors"
          >
            <User className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
