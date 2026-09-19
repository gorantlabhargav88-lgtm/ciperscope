import type { FC } from 'react';
import { NavLink } from 'react-router-dom';
import { TerminalSquare } from 'lucide-react';
import { cn } from '../lib/utils';
import { NAVIGATION } from '../config/navigation';
import type { NavItem } from '../config/navigation';

const NavItemLink: FC<NavItem> = ({ to, icon: Icon, label }) => {
  return (
    <NavLink
      to={to}
      className={({ isActive }) => cn(
        "flex items-center px-3 py-2 text-sm rounded-md transition-colors",
        isActive
          ? "bg-primary/10 text-primary font-medium"
          : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
      )}
    >
      <Icon className="w-4 h-4 mr-3" />
      {label}
    </NavLink>
  );
};

export const Sidebar = () => {
  return (
    <aside className="w-64 bg-background border-r border-border flex flex-col h-full hidden md:flex">
      <div className="h-16 flex items-center px-6 border-b border-border">
        <TerminalSquare className="w-6 h-6 text-primary mr-2" />
        <span className="font-semibold text-lg text-foreground tracking-wide">CiperScope</span>
      </div>

      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-6">
        {NAVIGATION.map((group) => (
          <div key={group.label}>
            <div className="px-3 text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
              {group.label}
            </div>
            <div className="space-y-1">
              {group.items.map((item) => (
                <NavItemLink key={item.to} {...item} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
};
