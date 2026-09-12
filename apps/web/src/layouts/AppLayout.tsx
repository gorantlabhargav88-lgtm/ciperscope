import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { CommandPalette } from '../components/CommandPalette';

export const AppLayout = () => {
  return (
    <div className="flex h-screen bg-slate-950 text-slate-50 overflow-hidden">
      <CommandPalette />
      <Sidebar />
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
