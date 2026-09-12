import type { FC } from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, Search, ShieldAlert, Briefcase, 
  Mail, Archive, Link as LinkIcon, CheckCircle, Clock, 
  Map, FileText, BarChart2, Plug, ShieldCheck, Users, Settings, 
  TerminalSquare
} from 'lucide-react';
import { cn } from '../lib/utils';

interface NavItemProps {
  to: string;
  icon: React.ElementType;
  label: string;
}

const NavItem: FC<NavItemProps> = ({ to, icon: Icon, label }) => {
  return (
    <NavLink 
      to={to}
      className={({ isActive }) => cn(
        "flex items-center px-3 py-2 text-sm rounded-md transition-colors",
        isActive 
          ? "bg-blue-600/10 text-blue-500 font-medium" 
          : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
      )}
    >
      <Icon className="w-4 h-4 mr-3" />
      {label}
    </NavLink>
  );
};

export const Sidebar = () => {
  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800 flex flex-col h-full hidden md:flex">
      <div className="h-16 flex items-center px-6 border-b border-slate-800">
        <TerminalSquare className="w-6 h-6 text-blue-500 mr-2" />
        <span className="font-semibold text-lg text-slate-100 tracking-wide">CiperScope</span>
      </div>
      
      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-6">
        
        <div>
          <div className="px-3 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Command Center</div>
          <div className="space-y-1">
            <NavItem to="/overview" icon={LayoutDashboard} label="Overview" />
            <NavItem to="/investigations" icon={Search} label="Investigations" />
            <NavItem to="/alerts" icon={ShieldAlert} label="Alerts" />
            <NavItem to="/cases" icon={Briefcase} label="Cases" />
          </div>
        </div>

        <div>
          <div className="px-3 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Forensics</div>
          <div className="space-y-1">
            <NavItem to="/email-analysis" icon={Mail} label="Email Analysis" />
            <NavItem to="/evidence" icon={Archive} label="Evidence Vault" />
            <NavItem to="/chain-of-custody" icon={LinkIcon} label="Chain of Custody" />
            <NavItem to="/verification" icon={CheckCircle} label="Verification" />
            <NavItem to="/timeline" icon={Clock} label="Timeline" />
          </div>
        </div>

        <div>
          <div className="px-3 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Intelligence</div>
          <div className="space-y-1">
            <NavItem to="/geo-intelligence" icon={Map} label="Geo Intelligence" />
            <NavItem to="/reports" icon={FileText} label="Reports" />
            <NavItem to="/analytics" icon={BarChart2} label="Analytics" />
          </div>
        </div>

        <div>
          <div className="px-3 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">System</div>
          <div className="space-y-1">
            <NavItem to="/integrations" icon={Plug} label="Integrations" />
            <NavItem to="/audit-log" icon={ShieldCheck} label="Audit Log" />
            <NavItem to="/users" icon={Users} label="Users & Roles" />
            <NavItem to="/settings" icon={Settings} label="Settings" />
          </div>
        </div>

      </div>
    </aside>
  );
};
