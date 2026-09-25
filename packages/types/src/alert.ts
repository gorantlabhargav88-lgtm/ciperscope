/**
 * Alerts — GET/PATCH /alerts (services/api/src/modules/alert/alert.routes.ts).
 * This is the only notification substrate in the codebase: no WebSocket/
 * SSE/pub-sub infrastructure exists, so the header notification bell
 * (apps/web/src/layouts/Header.tsx) polls the same Alert table this page
 * already reads — never a second notification model.
 */
export type AlertSeverityValue = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface AlertItem {
  id: string;
  organizationId: string;
  caseId: string | null;
  title: string;
  message: string;
  severity: AlertSeverityValue;
  isRead: boolean;
  createdAt: string;
}

export interface AlertListResponse {
  items: AlertItem[];
  nextCursor: string | null;
}
