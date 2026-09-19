import type { CaseStatus, Priority } from './severity';

export interface RecentCase {
  id: string;
  title: string;
  priority: Priority;
  status: CaseStatus;
  timestamp: string;
}

export interface DashboardOverview {
  activeThreats: number;
  criticalAlerts: number;
  investigations: number;
  emailsAnalyzed: number;
  indicatorsTracked: number;
  priorityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  recentAlerts: RecentCase[];
}
