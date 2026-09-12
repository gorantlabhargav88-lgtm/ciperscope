import { AlertTriangle } from 'lucide-react';

export const DemoModeBanner = () => {
  return (
    <div className="bg-amber-500/10 border-l-4 border-amber-500 text-amber-500 px-4 py-2 flex items-center text-sm font-medium">
      <AlertTriangle className="w-4 h-4 mr-2" />
      DEMO MODE: Data is simulated. Backend integration pending.
    </div>
  );
};
