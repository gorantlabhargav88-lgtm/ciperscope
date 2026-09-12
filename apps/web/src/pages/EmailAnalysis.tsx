import { useState, useRef, useEffect } from 'react';
import { Mail, FileText, Server, UploadCloud, Loader2, CheckCircle, XCircle } from 'lucide-react';
import { DemoModeBanner } from '../components/DemoModeBanner';

export const EmailAnalysis = () => {
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<{message?: string, error?: string, duplicate?: boolean, emailId?: string} | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [analysis, setAnalysis] = useState<any>(null);
  const [headers, setHeaders] = useState<any[]>([]);
  const [hops, setHops] = useState<any[]>([]);
  const [mimeParts, setMimeParts] = useState<any[]>([]);
  
  const organizationId = '00000000-0000-0000-0000-000000000000'; // dummy for UI

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setUploadResult(null);
    setAnalysis(null);
    setHeaders([]);
    setHops([]);
    setMimeParts([]);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const res = await fetch('http://localhost:3000/api/v1/emails/ingest', {
        method: 'POST',
        headers: {
          'x-organization-id': organizationId
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

  useEffect(() => {
    let interval: any;
    if (uploadResult?.emailId) {
      const fetchDetails = async () => {
        try {
          const res = await fetch(`http://localhost:3000/api/v1/emails/${uploadResult.emailId}/analysis`, {
            headers: { 'x-organization-id': organizationId }
          });
          const data = await res.json();
          setAnalysis(data);

          if (data.analysisStatus === 'COMPLETED') {
            clearInterval(interval);
            
            // Fetch headers
            fetch(`http://localhost:3000/api/v1/emails/${uploadResult.emailId}/headers`, {
              headers: { 'x-organization-id': organizationId }
            }).then(r => r.json()).then(d => setHeaders(d.headers || []));
            
            // Fetch hops
            fetch(`http://localhost:3000/api/v1/emails/${uploadResult.emailId}/received-hops`, {
              headers: { 'x-organization-id': organizationId }
            }).then(r => r.json()).then(d => setHops(d.hops || []));
            
            // Fetch mime
            fetch(`http://localhost:3000/api/v1/emails/${uploadResult.emailId}/mime-parts`, {
              headers: { 'x-organization-id': organizationId }
            }).then(r => r.json()).then(d => setMimeParts(d.mimeParts || []));
          } else if (data.analysisStatus === 'FAILED') {
            clearInterval(interval);
          }
        } catch (e) {
          console.error(e);
        }
      };

      interval = setInterval(fetchDetails, 2000);
      fetchDetails();
    }
    return () => clearInterval(interval);
  }, [uploadResult?.emailId]);

  const getHeader = (name: string) => headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value;

  return (
    <div className="space-y-6 pb-20">
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
          {analysis && (
             <div className="text-right flex items-center gap-3">
               <div className="text-sm font-medium text-slate-400">Status</div>
               {analysis.analysisStatus === 'PROCESSING' || analysis.analysisStatus === 'PENDING' ? (
                  <Loader2 className="w-5 h-5 animate-spin text-indigo-400" />
               ) : analysis.analysisStatus === 'COMPLETED' ? (
                  <CheckCircle className="w-5 h-5 text-emerald-400" />
               ) : (
                  <XCircle className="w-5 h-5 text-rose-500" />
               )}
             </div>
          )}
        </div>
      </div>

      {!analysis && !uploadResult && (
        <div className="p-8 text-center text-slate-500 border border-slate-800 rounded-lg border-dashed">
          Upload an .eml file to begin analysis.
        </div>
      )}

      {analysis?.analysisStatus === 'COMPLETED' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            
            {/* Header Forensics */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
                <h2 className="font-medium text-slate-200">Header Information</h2>
                <span className="text-xs bg-slate-800 text-slate-300 px-2 py-1 rounded">Parsed</span>
              </div>
              <div className="p-5 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="text-sm text-slate-400">From</div>
                  <div className="md:col-span-3 text-sm font-medium text-slate-200">{getHeader('from') || 'N/A'}</div>

                  <div className="text-sm text-slate-400">To</div>
                  <div className="md:col-span-3 text-sm text-slate-200">{getHeader('to') || 'N/A'}</div>

                  <div className="text-sm text-slate-400">Subject</div>
                  <div className="md:col-span-3 text-sm text-slate-200">{getHeader('subject') || 'N/A'}</div>

                  <div className="text-sm text-slate-400">Date</div>
                  <div className="md:col-span-3 text-sm text-slate-200">{getHeader('date') || 'N/A'}</div>
                  
                  <div className="text-sm text-slate-400">Message-ID</div>
                  <div className="md:col-span-3 text-sm text-slate-400 font-mono break-all">{getHeader('message-id') || 'N/A'}</div>
                </div>
              </div>
            </div>

            {/* Transport Trace */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50">
                <h2 className="font-medium text-slate-200">Transport Trace (Received Hops)</h2>
              </div>
              <div className="p-5">
                <div className="flex flex-col space-y-6 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-slate-800">
                  {hops.map((hop, idx) => (
                    <div key={idx} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                      <div className="flex items-center justify-center w-10 h-10 rounded-full border border-slate-700 bg-slate-900 text-slate-400 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2">
                        <Server className="w-5 h-5" />
                      </div>
                      <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] p-4 rounded-lg border border-slate-800 bg-slate-950/50">
                        <div className="flex items-center justify-between mb-1">
                          <div className="font-medium text-sm text-slate-200">Hop {idx}</div>
                          {hop.sourceIp && <span className="text-xs text-slate-400 font-medium font-mono">{hop.sourceIp}</span>}
                        </div>
                        <div className="text-xs text-slate-500 line-clamp-3" title={hop.receivedHeader}>{hop.receivedHeader}</div>
                      </div>
                    </div>
                  ))}
                  {hops.length === 0 && <div className="text-sm text-slate-500 text-center w-full">No Received hops detected.</div>}
                </div>
              </div>
            </div>
            
            {/* Authentication Observations */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/50 flex justify-between items-center">
                <h2 className="font-medium text-slate-200">Authentication Observations</h2>
                <span className="text-xs bg-amber-500/20 text-amber-500 px-2 py-1 rounded">Unverified (Phase 8)</span>
              </div>
              <div className="p-5">
                 {headers.filter(h => h.name.toLowerCase() === 'authentication-results').map((h, i) => (
                    <div key={i} className="mb-2 p-3 bg-slate-950 border border-slate-800 rounded text-sm text-slate-300 font-mono break-all">
                      {h.value}
                    </div>
                 ))}
                 {headers.filter(h => h.name.toLowerCase() === 'authentication-results').length === 0 && (
                   <div className="text-sm text-slate-500">No Authentication-Results headers found.</div>
                 )}
              </div>
            </div>

          </div>

          {/* Right Column: MIME Tree */}
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
              <h2 className="font-medium text-slate-200 mb-4 flex items-center">
                <FileText className="w-5 h-5 mr-2 text-slate-400" />
                MIME Tree
              </h2>
              <div className="space-y-3">
                {mimeParts.map((part, i) => (
                  <div key={i} className="p-3 bg-slate-950 border border-slate-800 rounded flex flex-col items-start">
                    <div className="text-sm font-medium text-slate-200 flex items-center w-full justify-between">
                       <span>{part.partIndex}. {part.filename || 'Part'}</span>
                       <span className="text-xs bg-slate-800 px-1.5 py-0.5 rounded text-slate-400">{part.contentType}</span>
                    </div>
                    <div className="text-xs text-slate-500 mt-2">
                       Size: {part.sizeBytes ? Math.round(part.sizeBytes / 1024) + ' KB' : 'Unknown'}
                       {part.isAttachment && <span className="ml-2 text-amber-500 border border-amber-500/20 bg-amber-500/10 px-1 rounded">Attachment</span>}
                    </div>
                  </div>
                ))}
                {mimeParts.length === 0 && (
                   <div className="text-sm text-slate-500">No MIME parts detected.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
