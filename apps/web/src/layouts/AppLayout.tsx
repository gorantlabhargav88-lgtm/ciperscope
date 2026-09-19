import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { CommandPalette } from '../components/CommandPalette';
import { CommandPaletteProvider } from '../components/command-palette/CommandPaletteContext';

export const AppLayout = () => {
  return (
    <CommandPaletteProvider>
      <div className="flex h-screen bg-background text-foreground overflow-hidden">
        <CommandPalette />
        <Sidebar />
        <div className="flex-1 flex flex-col h-full overflow-hidden">
          <Header />
          <main className="flex-1 overflow-y-auto p-6">
            <Outlet />
          </main>
        </div>
      </div>
    </CommandPaletteProvider>
  );
};
