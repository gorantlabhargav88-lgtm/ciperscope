import { ShieldOff } from 'lucide-react';
import { Link } from 'react-router-dom';

export const Unauthorized = () => {
  return (
    <div className="flex flex-col h-full items-center justify-center text-center space-y-4">
      <ShieldOff className="w-12 h-12 text-security-critical" />
      <div>
        <h1 className="text-xl font-semibold text-foreground">Access denied</h1>
        <p className="text-muted-foreground mt-1 max-w-sm">
          Your role does not have permission to view this section.
        </p>
      </div>
      <Link to="/overview" className="text-primary text-sm hover:underline">
        Back to Command Center
      </Link>
    </div>
  );
};
