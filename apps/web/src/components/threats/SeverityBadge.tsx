import type { FC } from 'react';
import { AlertCircle, ShieldAlert, Shield, Info } from 'lucide-react';
import { cn } from '../../lib/utils';
import type { AlertSeverity } from '../../types/severity';

const MAP: Record<AlertSeverity, { icon: typeof AlertCircle; cls: string }> = {
  CRITICAL: { icon: AlertCircle, cls: 'bg-security-critical/10 text-security-critical border-security-critical/20' },
  HIGH: { icon: ShieldAlert, cls: 'bg-security-high/10 text-security-high border-security-high/20' },
  MEDIUM: { icon: Shield, cls: 'bg-security-medium/10 text-security-medium border-security-medium/20' },
  LOW: { icon: Shield, cls: 'bg-security-low/10 text-security-low border-security-low/20' },
  INFO: { icon: Info, cls: 'bg-security-info/10 text-security-info border-security-info/20' },
};

export const SeverityBadge: FC<{ level: AlertSeverity; className?: string }> = ({ level, className }) => {
  const { icon: Icon, cls } = MAP[level];
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border', cls, className)}>
      <Icon className="w-3 h-3 mr-1" />
      {level}
    </span>
  );
};
