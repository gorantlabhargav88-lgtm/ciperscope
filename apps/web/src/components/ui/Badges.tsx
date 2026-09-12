import type { ReactNode, FC } from 'react';
import { cn } from '../../lib/utils';
import { AlertCircle, ShieldAlert, Shield, ShieldCheck, Info } from 'lucide-react';

interface BadgeProps {
  className?: string;
  children: ReactNode;
}

export const Badge: FC<BadgeProps> = ({ className, children }) => (
  <span className={cn("inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border", className)}>
    {children}
  </span>
);

export const ThreatScore: FC<{ score: number }> = ({ score }) => {
  let colorClass = "bg-slate-500/10 text-slate-500 border-slate-500/20";
  if (score >= 90) colorClass = "bg-rose-500/10 text-rose-500 border-rose-500/20";
  else if (score >= 70) colorClass = "bg-orange-500/10 text-orange-500 border-orange-500/20";
  else if (score >= 40) colorClass = "bg-amber-500/10 text-amber-500 border-amber-500/20";
  else if (score >= 10) colorClass = "bg-blue-500/10 text-blue-500 border-blue-500/20";
  else colorClass = "bg-emerald-500/10 text-emerald-500 border-emerald-500/20";

  return (
    <div className={cn("flex items-center space-x-1 font-bold", colorClass, "px-2 py-1 rounded w-fit")}>
      <span>{score}</span>
      <span className="text-[10px] opacity-70">/100</span>
    </div>
  );
};

export const SeverityBadge: FC<{ level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' }> = ({ level }) => {
  const map = {
    CRITICAL: { icon: AlertCircle, cls: "bg-rose-500/10 text-rose-500 border-rose-500/20" },
    HIGH: { icon: ShieldAlert, cls: "bg-orange-500/10 text-orange-500 border-orange-500/20" },
    MEDIUM: { icon: Shield, cls: "bg-amber-500/10 text-amber-500 border-amber-500/20" },
    LOW: { icon: Shield, cls: "bg-blue-500/10 text-blue-500 border-blue-500/20" },
    INFO: { icon: Info, cls: "bg-slate-500/10 text-slate-500 border-slate-500/20" },
  };
  const Icon = map[level].icon;

  return (
    <Badge className={map[level].cls}>
      <Icon className="w-3 h-3 mr-1" />
      {level}
    </Badge>
  );
};

export const IntegrityBadge: FC<{ status: 'VERIFIED' | 'TAMPERED' | 'PENDING' }> = ({ status }) => {
  if (status === 'VERIFIED') return <Badge className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20"><ShieldCheck className="w-3 h-3 mr-1"/> Verified</Badge>;
  if (status === 'TAMPERED') return <Badge className="bg-rose-500/10 text-rose-500 border-rose-500/20"><AlertCircle className="w-3 h-3 mr-1"/> Tampered</Badge>;
  return <Badge className="bg-slate-500/10 text-slate-500 border-slate-500/20">Pending</Badge>;
};
