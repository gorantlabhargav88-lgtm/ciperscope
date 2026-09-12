import type { FC } from 'react';
import { Settings } from 'lucide-react';
import { DemoModeBanner } from '../components/DemoModeBanner';

interface PlaceholderPageProps {
  title: string;
}

export const PlaceholderPage: FC<PlaceholderPageProps> = ({ title }) => {
  return (
    <div className="flex flex-col h-full space-y-6">
      <DemoModeBanner />
      <div>
        <h1 className="text-2xl font-semibold text-slate-100">{title}</h1>
        <p className="text-slate-400 mt-1">Integration pending backend implementation.</p>
      </div>
      
      <div className="flex-1 flex items-center justify-center border border-slate-800 border-dashed rounded-lg bg-slate-900/50">
        <div className="text-center">
          <Settings className="w-12 h-12 text-slate-700 mx-auto mb-4 animate-spin-slow" />
          <h2 className="text-lg font-medium text-slate-300">Module Under Construction</h2>
          <p className="text-sm text-slate-500 mt-2 max-w-sm">
            This section will be available once the corresponding Phase 6+ backend microservices are deployed.
          </p>
        </div>
      </div>
    </div>
  );
};
