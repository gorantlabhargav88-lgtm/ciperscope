import { useState, useRef } from 'react';
import { Mail, Shield, FileText, Globe, Server, Link, UploadCloud, Loader2 } from 'lucide-react';
import { DemoModeBanner } from '../components/DemoModeBanner';

export const EmailAnalysis = () => {
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<{message?: string, error?: string, duplicate?: boolean} | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setUploadResult(null);
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const res = await fetch('http://localhost:3000/api/v1/emails/ingest', {
        method: 'POST',
        headers: {
          // Dummy organization ID for UI
          'x-organization-id': '00000000-0000-0000-0000-000000000000'
        },
        body: formData
      });
      const data = await res.json();
      setUploadResult(res.ok ? data : { error: data.message || 'Upload failed' });
    } catch (err: any) {
      setUploadResult({ error: err.message });
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-6">
      <DemoModeBanner />
      
      <div className="flex justify-between items-start">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100 flex items-center">
            <Mail className="w-6 h-6 mr-3 text-slate-400" />
            Email Investigation
          </h1>
          <p className="text-slate-400 mt-1">Detailed forensics and threat analysis of the email artifact.</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex flex-col items-end">
            <input 
               type="file" 
               ref={fileInputRef} 
               className="hidden" 
               accept=".eml" 
               onChange={handleFileUpload} 
            />
            <button 
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg font-medium text-sm flex items-center transition-colors disabled:opacity-50"
            >
              {uploading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <UploadCloud className="w-4 h-4 mr-2" />}
              {uploading ? 'Ingesting...' : 'Ingest Raw Email'}
            </button>
            {uploadResult && (
               <div className={`text-xs mt-2 ${uploadResult.error ? 'text-rose-400' : (uploadResult.duplicate ? 'text-amber-400' : 'text-emerald-400')}`}>
                 {uploadResult.error || uploadResult.message}
               </div>
            )}
          </div>
          <div className="text-right">
            <div className="text-sm font-medium text-slate-400">Risk Score</div>
            <div className="text-xl font-bold text-rose-500">89/100</div>
          </div>
          <div className="h-10 w-10 rounded bg-rose-500/10 border border-rose-500/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-rose-500" />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Metadata */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
              <h2 className="font-medium text-slate-200">Header Information</h2>
              <span className="text-xs bg-slate-800 text-slate-300 px-2 py-1 rounded">Parsed</span>
            </div>
            <div className="p-5 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="text-sm text-slate-400">From</div>
                <div className="md:col-span-3 text-sm font-medium text-slate-200 flex items-center">
                  admin@paypal-security-update.com
                  <span className="ml-3 px-2 py-0.5 rounded border border-rose-500/20 bg-rose-500/10 text-rose-500 text-xs">Phishing Domain</span>
                </div>

                <div className="text-sm text-slate-400">To</div>
                <div className="md:col-span-3 text-sm text-slate-200">target.user@enterprise.com</div>

                <div className="text-sm text-slate-400">Subject</div>
                <div className="md:col-span-3 text-sm text-slate-200">URGENT: Your account has been suspended</div>

                <div className="text-sm text-slate-400">Date</div>
                <div className="md:col-span-3 text-sm text-slate-200">Oct 24, 2023, 14:32:01 UTC</div>
                
                <div className="text-sm text-slate-400">Message-ID</div>
                <div className="md:col-span-3 text-sm text-slate-400 font-mono break-all">&lt;202310241432.89423@mail.paypal-security-update.com&gt;</div>
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50">
              <h2 className="font-medium text-slate-200">Authentication & Relay Path</h2>
            </div>
            <div className="p-5">
              <div className="flex flex-col space-y-6 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-slate-800">
                <div className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                  <div className="flex items-center justify-center w-10 h-10 rounded-full border border-slate-700 bg-slate-900 text-slate-400 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2">
                    <Server className="w-5 h-5" />
                  </div>
                  <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] p-4 rounded-lg border border-slate-800 bg-slate-950/50">
                    <div className="flex items-center justify-between mb-1">
                      <div className="font-medium text-sm text-slate-200">Originating IP</div>
                      <span className="text-xs text-rose-500 font-medium">192.168.45.2 (Malicious)</span>
                    </div>
                    <div className="text-xs text-slate-500">Ukraine (UA) AS12345</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Indicators & Actions */}
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h2 className="font-medium text-slate-200 mb-4">Indicators of Compromise</h2>
            <div className="space-y-3">
              <div className="p-3 bg-slate-950 border border-slate-800 rounded flex items-start">
                <Globe className="w-4 h-4 text-rose-500 mt-0.5 mr-3 shrink-0" />
                <div>
                  <div className="text-sm font-medium text-slate-200">paypal-security-update.com</div>
                  <div className="text-xs text-slate-500 mt-1">Domain Age: 2 days</div>
                </div>
              </div>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded flex items-start">
                <FileText className="w-4 h-4 text-orange-500 mt-0.5 mr-3 shrink-0" />
                <div>
                  <div className="text-sm font-medium text-slate-200">invoice_urgent.pdf.exe</div>
                  <div className="text-xs text-slate-500 mt-1">Attachment (Hidden Extension)</div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h2 className="font-medium text-slate-200 mb-4">Chain of Custody</h2>
            <div className="flex items-center text-sm text-emerald-500 mb-4">
              <Link className="w-4 h-4 mr-2" />
              Evidence Blockchain Anchored
            </div>
            <button className="w-full bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium py-2 px-4 rounded transition-colors text-sm border border-slate-700">
              Verify Integrity
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
