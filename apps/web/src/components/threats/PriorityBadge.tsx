import type { FC } from 'react';
import { cn } from '../../lib/utils';
import { toPriorityTier } from '../../types/severity';
import type { Priority } from '../../types/severity';
import { Tooltip, TooltipTrigger, TooltipContent } from '../ui/tooltip';

const TIER_STYLES: Record<string, string> = {
  P1: 'bg-security-critical/10 text-security-critical border-security-critical/20',
  P2: 'bg-security-high/10 text-security-high border-security-high/20',
  P3: 'bg-security-low/10 text-security-low border-security-low/20',
};

const TIER_LABEL: Record<string, string> = {
  P1: 'P1 · Critical',
  P2: 'P2 · High',
  P3: 'P3',
};

export const PriorityBadge: FC<{ priority: Priority; className?: string }> = ({ priority, className }) => {
  const tier = toPriorityTier(priority);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={cn(
            'inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border cursor-default',
            TIER_STYLES[tier],
            className
          )}
        >
          {TIER_LABEL[tier]}
        </span>
      </TooltipTrigger>
      <TooltipContent>Underlying priority: {priority}</TooltipContent>
    </Tooltip>
  );
};
