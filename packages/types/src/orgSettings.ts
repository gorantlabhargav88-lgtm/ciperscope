/**
 * Organization Settings — GET/PATCH /settings
 * (services/api/src/modules/settings/settings.routes.ts). Reuses
 * Organization.name and the previously-unused SystemSetting key/value
 * table; never a fabricated settings model or field.
 */
export type AutoCaseRiskThreshold = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NEVER';

export interface OrgSettingsOrganization {
  id: string;
  name: string;
  domain: string | null;
  createdAt: string;
}

export interface OrgSettingsPreferences {
  notifyOnCriticalCase: boolean;
  notifyOnThreatDetected: boolean;
  autoCaseRiskThreshold: AutoCaseRiskThreshold;
  evidenceRetentionDays: number;
}

export interface OrgSettingsResponse {
  organization: OrgSettingsOrganization;
  preferences: OrgSettingsPreferences;
}

export interface UpdateOrgSettingsInput {
  displayName?: string;
  notifyOnCriticalCase?: boolean;
  notifyOnThreatDetected?: boolean;
  autoCaseRiskThreshold?: AutoCaseRiskThreshold;
  evidenceRetentionDays?: number;
}
