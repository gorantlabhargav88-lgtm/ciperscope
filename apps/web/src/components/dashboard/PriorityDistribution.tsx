import type { FC } from 'react';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

export interface PriorityBreakdown {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

// Matches --color-security-* in src/index.css
const P1_COLOR = '#e11d48';
const P2_COLOR = '#f97316';
const P3_COLOR = '#3b82f6';

interface PriorityDistributionProps {
  breakdown: PriorityBreakdown;
}

/** Real, tenant-scoped open-case counts grouped by Priority, presented as P1/P2/P3. */
export const PriorityDistribution: FC<PriorityDistributionProps> = ({ breakdown }) => {
  const data = [
    { tier: 'P1', label: 'Critical', count: breakdown.critical, color: P1_COLOR },
    { tier: 'P2', label: 'High', count: breakdown.high, color: P2_COLOR },
    { tier: 'P3', label: 'Medium + Low', count: breakdown.medium + breakdown.low, color: P3_COLOR },
  ];

  const allZero = data.every((d) => d.count === 0);

  if (allZero) {
    return (
      <div className="flex flex-col items-center justify-center h-64 border border-dashed border-border rounded bg-background/50">
        <span className="text-muted-foreground text-sm">No open cases to prioritize right now.</span>
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={data} layout="vertical" margin={{ left: 12, right: 24 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" horizontal={false} />
        <XAxis type="number" allowDecimals={false} tick={{ fill: 'var(--color-muted-foreground)', fontSize: 12 }} stroke="var(--color-border)" />
        <YAxis
          type="category"
          dataKey="tier"
          width={40}
          tick={{ fill: 'var(--color-foreground)', fontSize: 13, fontWeight: 600 }}
          stroke="var(--color-border)"
        />
        <Tooltip
          cursor={{ fill: 'var(--color-accent)', opacity: 0.3 }}
          contentStyle={{ background: 'var(--color-popover)', border: '1px solid var(--color-border)', borderRadius: 8 }}
          labelStyle={{ color: 'var(--color-foreground)' }}
          formatter={(value, _name, item) => [`${value} open cases`, item.payload.label]}
        />
        <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={28}>
          {data.map((d) => (
            <Cell key={d.tier} fill={d.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
};
