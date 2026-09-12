import { ShieldAlert, Activity, Server, AlertTriangle } from 'lucide-react';
import { DemoModeBanner } from '../components/DemoModeBanner';

export const Overview = () => {
  return (
    <div className="space-y-6">
      <DemoModeBanner />
      
      <div>
        <h1 className="text-2xl font-semibold text-slate-100">Command Center</h1>
        <p className="text-slate-400 mt-1">SOC Overview and Active Threats</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric Cards */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center text-rose-500 mb-2">
            <ShieldAlert className="w-5 h-5 mr-2" />
            <span className="font-medium">Active Threats</span>
          </div>
          <div className="text-3xl font-semibold text-slate-100">24</div>
        </div>
        
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center text-orange-500 mb-2">
            <AlertTriangle className="w-5 h-5 mr-2" />
            <span className="font-medium">Critical Alerts</span>
          </div>
          <div className="text-3xl font-semibold text-slate-100">12</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center text-blue-500 mb-2">
            <Activity className="w-5 h-5 mr-2" />
            <span className="font-medium">Investigations</span>
          </div>
          <div className="text-3xl font-semibold text-slate-100">8</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="flex items-center text-emerald-500 mb-2">
            <Server className="w-5 h-5 mr-2" />
            <span className="font-medium">System Status</span>
          </div>
          <div className="text-xl font-semibold text-slate-100 mt-1">All Systems Nominal</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-5 min-h-[400px]">
          <h2 className="font-medium text-slate-200 mb-4">Threat Timeline</h2>
          <div className="flex items-center justify-center h-64 border border-dashed border-slate-700 rounded bg-slate-950/50">
             <span className="text-slate-500 text-sm">Chart integration pending</span>
          </div>
        </div>
        
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
          <h2 className="font-medium text-slate-200 mb-4">Recent Alerts</h2>
          <div className="space-y-3">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="p-3 bg-slate-950 border border-slate-800 rounded-md">
                <div className="flex justify-between items-start">
                  <div className="font-medium text-sm text-slate-300">Suspicious Login Attempt</div>
                  <span className="text-xs text-orange-500 bg-orange-500/10 px-2 py-0.5 rounded border border-orange-500/20">HIGH</span>
                </div>
                <div className="text-xs text-slate-500 mt-2">10 minutes ago</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
