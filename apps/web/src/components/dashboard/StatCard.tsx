import type { FC, ReactNode } from 'react';
import { cn } from '../../lib/utils';

interface StatCardProps {
  icon: ReactNode;
  label: string;
  value: ReactNode;
  loading?: boolean;
  accentClassName?: string;
}

export const StatCard: FC<StatCardProps> = ({ icon, label, value, loading, accentClassName }) => {
  return (
    <div className="bg-card border border-border rounded-lg p-4">
      <div className={cn('flex items-center mb-2', accentClassName)}>
        {icon}
        <span className="font-medium ml-2 text-sm">{label}</span>
      </div>
      <div className="text-3xl font-semibold text-foreground">
        {loading ? <div className="h-8 w-16 bg-secondary rounded animate-pulse" /> : value}
      </div>
    </div>
  );
};
