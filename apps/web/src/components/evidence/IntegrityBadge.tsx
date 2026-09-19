import type { FC } from 'react';
import { ShieldCheck, AlertCircle, Clock } from 'lucide-react';
import { cn } from '../../lib/utils';

export type IntegrityStatus = 'VERIFIED' | 'TAMPERED' | 'PENDING';

/** Reflects Evidence chain-of-custody verification state. Never implies a blockchain anchor —
 * BlockchainAnchor is schema-only in this codebase (demo-seed data only), not a live feature. */
export const IntegrityBadge: FC<{ status: IntegrityStatus; className?: string }> = ({ status, className }) => {
  if (status === 'VERIFIED') {
    return (
      <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border bg-security-verified/10 text-security-verified border-security-verified/20', className)}>
        <ShieldCheck className="w-3 h-3 mr-1" /> Verified
      </span>
    );
  }
  if (status === 'TAMPERED') {
    return (
      <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border bg-security-critical/10 text-security-critical border-security-critical/20', className)}>
        <AlertCircle className="w-3 h-3 mr-1" /> Tampered
      </span>
    );
  }
  return (
    <span className={cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border bg-security-info/10 text-security-info border-security-info/20', className)}>
      <Clock className="w-3 h-3 mr-1" /> Pending
    </span>
  );
};
