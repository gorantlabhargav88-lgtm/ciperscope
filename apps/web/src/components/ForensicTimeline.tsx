import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, Link, Mail, Server, Fingerprint, Activity, Clock, AlertTriangle, Info } from 'lucide-react';
import { defangUrl } from '../lib/utils';
import { isAuthResultPass } from '@ciperscope/types';

interface TimelineEvent {
  id: string;
  type: string;
  title: string;
  description?: string;
  severity: 'info' | 'warning' | 'critical' | 'success';
  timestamp?: string;
  details?: Record<string, any>;
  icon: React.ElementType;
}

interface ForensicTimelineProps {
  analysis: any;
  headers: any[];
  spf: any[];
  dkim: any[];
  dmarc: any;
  urls: any[];
  mlInference: any;
}

export const ForensicTimeline: React.FC<ForensicTimelineProps> = ({
  analysis,
  headers,
  spf,
  dkim,
  dmarc,
  urls,
  mlInference
}) => {
  const events: TimelineEvent[] = [];

  // 1. Email Received
  const dateHeader = headers.find(h => h.name.toLowerCase() === 'date')?.value;
  events.push({
    id: 'email_received',
    type: 'EMAIL_RECEIVED',
    title: 'Email Received & Ingested',
    description: 'Email artifact was ingested by CiperScope',
    severity: 'info',
    timestamp: dateHeader || analysis?.createdAt,
    icon: Mail
  });

  // 2. Authentication Checks
  if (spf.length > 0) {
    const isPass = spf.some(s => isAuthResultPass(s.result));
    events.push({
      id: 'spf_check',
      type: 'SPF_CHECKED',
      title: 'SPF Verification',
      description: isPass ? 'SPF passed' : 'SPF failed',
      severity: isPass ? 'success' : 'warning',
      details: { checks: spf },
      icon: Shield
    });
  }

  if (dkim.length > 0) {
    const isPass = dkim.some(d => isAuthResultPass(d.result));
    events.push({
      id: 'dkim_check',
      type: 'DKIM_CHECKED',
      title: 'DKIM Verification',
      description: isPass ? 'DKIM passed' : 'DKIM failed',
      severity: isPass ? 'success' : 'warning',
      details: { checks: dkim },
      icon: Fingerprint
    });
  }

  if (dmarc) {
    const isPass = isAuthResultPass(dmarc.result);
    events.push({
      id: 'dmarc_check',
      type: 'DMARC_CHECKED',
      title: 'DMARC Policy Evaluation',
      description: isPass ? 'DMARC passed' : 'DMARC failed',
      severity: isPass ? 'success' : 'warning',
      details: { result: dmarc.result, policy: dmarc.policy },
      icon: Server
    });
  }

  // 3. URLs extracted
  if (urls && urls.length > 0) {
    events.push({
      id: 'urls_extracted',
      type: 'URL_EXTRACTED',
      title: `${urls.length} URLs Extracted`,
      description: 'URLs were parsed and defanged for safety',
      severity: 'info',
      details: {
        urls: urls.map(u => ({ ...u, defanged: defangUrl(u.url) }))
      },
      icon: Link
    });
  }

  // 4. ML Classification
  if (mlInference && mlInference.status !== 'NOT_AVAILABLE') {
    const isHighRisk = mlInference.probability > 0.5;
    events.push({
      id: 'ml_classified',
      type: 'ML_CLASSIFIED',
      title: 'ML Classification (DistilBERT)',
      description: `Probability of threat: ${(mlInference.probability * 100).toFixed(1)}%`,
      severity: isHighRisk ? 'critical' : 'success',
      details: mlInference,
      icon: Activity
    });
  }

  // 5. Fusion Evaluated
  if (analysis?.riskAssessment?.factors) {
    const factors = analysis.riskAssessment.factors;
    if (factors.length > 0) {
      events.push({
        id: 'fusion_evaluated',
        type: 'FUSION_EVALUATED',
        title: 'FusionEngine Evaluation',
        description: `Aggregated ${factors.length} risk factors`,
        severity: analysis.riskAssessment.riskScore > 60 ? 'critical' : (analysis.riskAssessment.riskScore > 30 ? 'warning' : 'info'),
        details: { factors },
        icon: ShieldAlert
      });
    }
  }

  // 6. Verdict Generated
  if (analysis?.riskAssessment) {
    const level = analysis.riskAssessment.riskLevel;
    let severity: 'success' | 'warning' | 'critical' | 'info' = 'info';
    let icon = ShieldCheck;

    if (level === 'CRITICAL' || level === 'HIGH') {
       severity = 'critical';
       icon = AlertTriangle;
    } else if (level === 'MEDIUM') {
       severity = 'warning';
       icon = Info;
    } else if (level === 'LOW') {
       severity = 'success';
    }

    events.push({
      id: 'verdict_generated',
      type: 'VERDICT_GENERATED',
      title: 'Final Verdict',
      description: `Risk Level: ${level} (Score: ${analysis.riskAssessment.riskScore})`,
      severity,
      icon
    });
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-rose-500 bg-rose-500/10 border-rose-500/20';
      case 'warning': return 'text-amber-500 bg-amber-500/10 border-amber-500/20';
      case 'success': return 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20';
      default: return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
    }
  };

  const getIconColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-rose-500';
      case 'warning': return 'text-amber-500';
      case 'success': return 'text-emerald-500';
      default: return 'text-blue-400';
    }
  };

  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700 p-6">
      <h3 className="text-lg font-medium text-white mb-6 flex items-center">
        <Clock className="w-5 h-5 mr-2 text-indigo-400" />
        Forensic Timeline
      </h3>

      <div className="space-y-6 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-slate-700 before:to-transparent">
        {events.map((event) => {
          const Icon = event.icon;
          return (
            <div key={event.id} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
              <div className="flex items-center justify-center w-10 h-10 rounded-full border-4 border-slate-900 bg-slate-800 shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 shadow">
                <Icon className={`w-4 h-4 ${getIconColor(event.severity)}`} />
              </div>
              <div className={`w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] p-4 rounded-xl border ${getSeverityColor(event.severity)} backdrop-blur-sm`}>
                <div className="flex items-center justify-between space-x-2 mb-1">
                  <div className="font-bold text-slate-100">{event.title}</div>
                  <time className="text-xs font-medium text-slate-400">{event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'N/A'}</time>
                </div>
                <div className="text-slate-300 text-sm mb-2">{event.description}</div>

                {/* Details Render */}
                {event.details && (
                  <div className="mt-3 pt-3 border-t border-slate-700/50 text-xs">
                    {event.type === 'URL_EXTRACTED' && (
                      <div className="space-y-2">
                        {event.details.urls.slice(0, 5).map((u: any, i: number) => (
                          <div key={i} className="bg-slate-900/50 p-2 rounded break-all text-slate-400">
                            {u.defanged}
                          </div>
                        ))}
                        {event.details.urls.length > 5 && (
                          <div className="text-slate-500 italic">...and {event.details.urls.length - 5} more</div>
                        )}
                      </div>
                    )}
                    {event.type === 'FUSION_EVALUATED' && (
                       <ul className="space-y-1">
                         {event.details.factors.map((f: any, i: number) => (
                           <li key={i} className="flex justify-between">
                             <span className="text-slate-400">{f.description}</span>
                             <span className="text-slate-300 font-medium">+{f.value}</span>
                           </li>
                         ))}
                       </ul>
                    )}
                    {event.type === 'ML_CLASSIFIED' && (
                      <div className="flex justify-between items-center bg-slate-900/50 p-2 rounded">
                        <span className="text-slate-400">Class: {event.details.label}</span>
                        <span className="text-slate-300 font-mono">{(event.details.probability).toFixed(4)}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
