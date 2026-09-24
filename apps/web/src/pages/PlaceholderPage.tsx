import type { FC } from 'react';
import { Construction } from 'lucide-react';

interface PlaceholderPageProps {
  title: string;
  /** The specific, real reason this capability isn't available — never a generic "coming soon". */
  reason?: string;
}

export const PlaceholderPage: FC<PlaceholderPageProps> = ({ title, reason }) => {
  return (
    <div className="flex flex-col h-full space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">{title}</h1>
        <p className="text-muted-foreground mt-1">Not available in this deployment.</p>
      </div>

      <div className="flex-1 flex items-center justify-center border border-border border-dashed rounded-lg bg-card/50">
        <div className="text-center">
          <Construction className="w-12 h-12 text-muted-foreground/60 mx-auto mb-4" />
          <h2 className="text-lg font-medium text-foreground/90">Not available in this deployment</h2>
          <p className="text-sm text-muted-foreground mt-2 max-w-sm">
            {reason ?? 'No backend capability for this exists yet. No data is being simulated here.'}
          </p>
        </div>
      </div>
    </div>
  );
};
