import {
  LayoutDashboard, Search, ShieldAlert, Briefcase,
  Mail, Archive, Link as LinkIcon, CheckCircle, Clock,
  Map, FileText, BarChart2, Plug, ShieldCheck, Users, Settings, Webhook, Server, Fingerprint,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

export interface NavItem {
  to: string;
  icon: LucideIcon;
  label: string;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAVIGATION: NavGroup[] = [
  {
    label: 'Command Center',
    items: [
      { to: '/overview', icon: LayoutDashboard, label: 'Overview' },
      { to: '/investigations', icon: Search, label: 'Investigations' },
      { to: '/alerts', icon: ShieldAlert, label: 'Alerts' },
      { to: '/cases', icon: Briefcase, label: 'Cases' },
    ],
  },
  {
    label: 'Forensics',
    items: [
      { to: '/email-analysis', icon: Mail, label: 'Email Analysis' },
      { to: '/evidence', icon: Archive, label: 'Evidence Vault' },
      { to: '/chain-of-custody', icon: LinkIcon, label: 'Chain of Custody' },
      { to: '/verification', icon: CheckCircle, label: 'Verification' },
      { to: '/timeline', icon: Clock, label: 'Timeline' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { to: '/geo-intelligence', icon: Map, label: 'Geo Intelligence' },
      { to: '/infrastructure', icon: Server, label: 'Infrastructure' },
      { to: '/indicators', icon: Fingerprint, label: 'Indicators' },
      { to: '/reports', icon: FileText, label: 'Reports' },
      { to: '/analytics', icon: BarChart2, label: 'Analytics' },
    ],
  },
  {
    label: 'System',
    items: [
      { to: '/integrations', icon: Plug, label: 'Integrations' },
      { to: '/webhooks', icon: Webhook, label: 'Webhooks' },
      { to: '/audit-log', icon: ShieldCheck, label: 'Audit Log' },
      { to: '/users', icon: Users, label: 'Users & Roles' },
      { to: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
];

export const ALL_NAV_ITEMS: NavItem[] = NAVIGATION.flatMap((group) => group.items);
