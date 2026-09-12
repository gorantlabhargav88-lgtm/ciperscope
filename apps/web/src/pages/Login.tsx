import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';
import { Shield } from 'lucide-react';

export const Login = () => {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    // Simulate login for Phase 5 demo
    login({
      id: 'usr_1',
      name: 'Demo Analyst',
      email: email || 'analyst@ciperscope.demo',
      role: 'SOC_ANALYST',
      organizationId: 'org_1'
    });
    navigate('/overview');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      <div className="max-w-md w-full p-8 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl">
        <div className="flex flex-col items-center mb-8">
          <Shield className="w-12 h-12 text-blue-500 mb-4" />
          <h1 className="text-2xl font-semibold text-slate-100">CiperScope</h1>
          <p className="text-slate-400 mt-2 text-sm">See the Threat. Trace the Evidence.</p>
        </div>
        
        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Email</label>
            <input 
              type="email" 
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-100 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="analyst@organization.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Password</label>
            <input 
              type="password" 
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-slate-100 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
            />
          </div>
          <button 
            type="submit" 
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-lg transition-colors mt-6"
          >
            Authenticate
          </button>
        </form>
      </div>
    </div>
  );
};
