import type { FC } from 'react';
import { Construction } from 'lucide-react';

interface PlaceholderPageProps {
  title: string;
}

export const PlaceholderPage: FC<PlaceholderPageProps> = ({ title }) => {
  return (
    <div className="flex flex-col h-full space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">{title}</h1>
        <p className="text-muted-foreground mt-1">This module is not yet implemented.</p>
      </div>

      <div className="flex-1 flex items-center justify-center border border-border border-dashed rounded-lg bg-card/50">
        <div className="text-center">
          <Construction className="w-12 h-12 text-muted-foreground/60 mx-auto mb-4" />
          <h2 className="text-lg font-medium text-foreground/90">Coming soon</h2>
          <p className="text-sm text-muted-foreground mt-2 max-w-sm">
            This section is planned but not yet built. No data is being simulated here.
          </p>
        </div>
      </div>
    </div>
  );
};
