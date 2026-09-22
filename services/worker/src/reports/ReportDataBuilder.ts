/**
 * Phase J — deterministic forensic report data contract (Step 2).
 *
 * A pure function over already-fetched Prisma rows (no DB/network access
 * here — the caller fetches once, this only shapes the result). Every
 * field distinguishes real, persisted evidence from genuinely unavailable
 * intelligence — nothing here is ever invented. Fields use `null` for
 * "not observed" and explicit status strings ('NOT_CONFIGURED',
 * 'UNAVAILABLE') where a source system exists but produced nothing.
 */

export interface ReportInput {
  reportId: string;
  organizationId: string;
  reportVersion: string;
  email: {
    id: string;
    messageId: string | null;
    subject: string | null;
    senderAddress: string | null;
    replyTo: string | null;
    returnPath: string | null;
    date: Date | null;
    createdAt: Date;
    analysisStatus: string;
    classification: string | null;
    riskScore: number | null;
  };
  addresses: Array<{ address: string; type: string }>;
  relayHops: Array<{ sourceIp: string | null; hopOrder: number; receivedHeader: string; timestamp: Date | null }>;
  spf: Array<{ result: string; domain: string | null; evaluatedIp: string | null; explanation: string | null }>;
  dkim: Array<{ result: string; domain: string | null; selector: string | null; explanation: string | null }>;
  dmarc: { result: string; orgDomain: string | null; policy: string | null; explanation: string | null } | null;
  urls: Array<{
    url: string; normalizedUrl: string | null; domain: string | null; source: string;
    isObfuscated: boolean; indicators: unknown;
  }>;
  attachments: Array<{
    id: string; filename: string; mimeType: string; sizeBytes: number; sha256: string | null;
    actualMimeType: string | null; isMismatch: boolean; isArchive: boolean; archiveMetadata: unknown;
    apkMetadata: unknown; qrFindings: unknown; threatIndicators: unknown;
  }>;
  geoLocations: Array<{ ipAddress: string; country: string | null; city: string | null; asn: string | null; isp: string | null; provider: string }>;
  indicatorObservations: Array<{ value: string; type: string; verdict: string; confidence: number | null; provider: string; observationTime: Date }>;
  riskAssessment: {
    overallScore: number;
    riskLevel: string;
    version: string;
    factors: Array<{ category: string; description: string; scoreContribution: number }>;
  } | null;
  mlInference: { status: string; prediction: string | null; modelScore: number | null } | null;
}

export interface ReportData {
  metadata: {
    reportId: string;
    emailId: string;
    organizationId: string;
    generatedAt: string;
    reportVersion: string;
    analysisStatus: string;
  };
  executiveSummary: {
    riskScore: number | null;
    riskLevel: string | null;
    classification: string | null;
    explanation: string;
  };
  emailOverview: {
    subject: string | null;
    sender: string | null;
    recipients: string[];
    replyTo: string | null;
    returnPath: string | null;
    date: string | null;
    messageId: string | null;
    ingestedAt: string;
    relayHops: Array<{ hopOrder: number; sourceIp: string | null; header: string }>;
  };
  authentication: {
    spf: Array<{ result: string; domain: string | null; evaluatedIp: string | null; explanation: string | null }>;
    dkim: Array<{ result: string; domain: string | null; selector: string | null; explanation: string | null }>;
    dmarc: { result: string; orgDomain: string | null; policy: string | null; explanation: string | null } | 'NOT_OBSERVED';
  };
  urlIntelligence: Array<{
    url: string; domain: string | null; source: string; isObfuscated: boolean; indicators: string[];
  }>;
  ipDomainIntelligence: Array<{
    ip: string;
    classification: 'PUBLIC' | 'PRIVATE_OR_RESERVED' | 'UNKNOWN';
    geolocation: { country: string | null; city: string | null; asn: string | null; isp: string | null; provider: string } | 'UNAVAILABLE';
    reputation: { verdict: string; provider: string; confidence: number | null } | 'NOT_OBSERVED';
  }>;
  attachments: Array<{
    filename: string;
    sha256: string | null;
    declaredMimeType: string;
    actualMimeType: string | null;
    mismatch: boolean;
    isArchive: boolean;
    apkMetadata: unknown | null;
    qrFindings: unknown | null;
    threatIndicators: string[];
  }>;
  cti: Array<{ indicator: string; type: string; verdict: string; provider: string; confidence: number | null; observedAt: string }>;
  evidenceGraphSummary: {
    urlCount: number;
    domainCount: number;
    ipCount: number;
    attachmentCount: number;
    apkCount: number;
    qrCodeCount: number;
    ctiObservationCount: number;
    geolocatedIpCount: number;
  };
  timeline: Array<{ timestamp: string | null; event: string; source: string; description: string }>;
  riskFactors: Array<{ category: string; description: string; scoreContribution: number }>;
  chainOfCustody: {
    attachmentHashes: Array<{ filename: string; sha256: string | null }>;
  };
  limitations: string[];
}

function classifyIpBasic(ip: string): 'PUBLIC' | 'PRIVATE_OR_RESERVED' | 'UNKNOWN' {
  // Deliberately minimal here (no external dependency needed for a
  // report-only classification) — matches the same RFC1918/loopback/
  // link-local ranges the real classifier (@ciperscope/http-client)
  // already enforces as the SSRF-relevant gate elsewhere in the pipeline.
  const v4 = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if (a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)) {
      return 'PRIVATE_OR_RESERVED';
    }
    return 'PUBLIC';
  }
  if (ip === '::1' || ip.toLowerCase().startsWith('fe80:') || ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) {
    return 'PRIVATE_OR_RESERVED';
  }
  if (ip.includes(':')) return 'PUBLIC';
  return 'UNKNOWN';
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function asIndicatorCategories(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((v) => (v && typeof v === 'object' && typeof (v as { category?: unknown }).category === 'string' ? (v as { category: string }).category : null))
    .filter((c): c is string => c !== null);
}

export function buildReportData(input: ReportInput): ReportData {
  const limitations: string[] = [];

  // --- Executive summary ---
  const riskLevel = input.riskAssessment?.riskLevel ?? null;
  const riskScore = input.riskAssessment?.overallScore ?? input.email.riskScore;
  let explanation: string;
  if (input.riskAssessment && input.riskAssessment.factors.length > 0) {
    explanation = `Risk assessed as ${riskLevel} (score ${riskScore}) based on ${input.riskAssessment.factors.length} deterministic finding(s): ${input.riskAssessment.factors.map((f) => f.category).join(', ')}.`;
  } else if (input.email.analysisStatus === 'COMPLETED') {
    explanation = 'Analysis completed with no corroborating risk factors identified.';
  } else {
    explanation = `Analysis status is ${input.email.analysisStatus}; a full risk assessment is not yet available.`;
    limitations.push(`Risk assessment unavailable — analysisStatus is ${input.email.analysisStatus}, not COMPLETED.`);
  }

  // --- Authentication ---
  if (!input.dmarc) limitations.push('No DMARC record/verification was observed for this email.');
  if (input.spf.length === 0) limitations.push('No SPF verification was performed or recorded.');
  if (input.dkim.length === 0) limitations.push('No DKIM verification was performed or recorded.');

  // --- IP/domain intelligence ---
  const geoByIp = new Map(input.geoLocations.map((g) => [g.ipAddress, g]));
  const indicatorByValue = new Map(input.indicatorObservations.map((o) => [o.value.toLowerCase(), o]));
  const uniqueIps = Array.from(new Set(input.relayHops.map((h) => h.sourceIp).filter((ip): ip is string => !!ip)));

  const ipDomainIntelligence = uniqueIps.map((ip) => {
    const geo = geoByIp.get(ip);
    const obs = indicatorByValue.get(ip.toLowerCase());
    if (!geo) limitations.push(`Geolocation unavailable for ${ip} (no configured provider or no data returned).`);
    return {
      ip,
      classification: classifyIpBasic(ip),
      geolocation: geo ? { country: geo.country, city: geo.city, asn: geo.asn, isp: geo.isp, provider: geo.provider } : 'UNAVAILABLE' as const,
      reputation: obs ? { verdict: obs.verdict, provider: obs.provider, confidence: obs.confidence } : 'NOT_OBSERVED' as const,
    };
  });

  // --- CTI (all observed indicators, not just IP) ---
  const cti = input.indicatorObservations.map((o) => ({
    indicator: o.value,
    type: o.type,
    verdict: o.verdict,
    provider: o.provider,
    confidence: o.confidence,
    observedAt: o.observationTime.toISOString(),
  }));
  if (cti.length === 0) limitations.push('No CTI observations were recorded — external threat-intelligence providers may not be configured.');

  // --- ML ---
  if (!input.mlInference || input.mlInference.status === 'NOT_AVAILABLE') {
    limitations.push('ML classification probability is unavailable (model service not configured or did not respond).');
  }

  // --- Evidence graph summary (counts only — the full graph is available
  // via GET /emails/:emailId/evidence-graph; this is a summary, per spec). ---
  const domainSet = new Set(input.urls.map((u) => u.domain).filter((d): d is string => !!d));
  let apkCount = 0;
  let qrCodeCount = 0;
  for (const a of input.attachments) {
    if (a.apkMetadata) apkCount++;
    const qr = a.qrFindings as { codes?: unknown[] } | null;
    if (qr && Array.isArray(qr.codes)) qrCodeCount += qr.codes.length;
  }

  // --- Timeline (chronological, from real timestamps only) ---
  const timeline: ReportData['timeline'] = [];
  timeline.push({ timestamp: input.email.createdAt.toISOString(), event: 'EMAIL_INGESTED', source: 'EMAIL_RECORD', description: 'Email artifact was ingested by CipherScope.' });
  for (const hop of input.relayHops) {
    if (hop.timestamp) {
      timeline.push({ timestamp: hop.timestamp.toISOString(), event: 'RELAY_HOP', source: 'RECEIVED_HEADER', description: `Relay hop ${hop.hopOrder}${hop.sourceIp ? ` from ${hop.sourceIp}` : ''}.` });
    }
  }
  for (const obs of input.indicatorObservations) {
    timeline.push({ timestamp: obs.observationTime.toISOString(), event: 'CTI_OBSERVATION', source: obs.provider, description: `${obs.provider} observed ${obs.value} as ${obs.verdict}.` });
  }
  if (input.riskAssessment) {
    timeline.push({ timestamp: null, event: 'RISK_ASSESSED', source: 'FUSION_ENGINE', description: `Risk assessed as ${input.riskAssessment.riskLevel} (score ${input.riskAssessment.overallScore}).` });
  }
  // Deterministic ordering: real timestamps first (chronological), then
  // undated events — never reordered by anything but the data itself.
  timeline.sort((a, b) => {
    if (a.timestamp && b.timestamp) return a.timestamp.localeCompare(b.timestamp);
    if (a.timestamp) return -1;
    if (b.timestamp) return 1;
    return 0;
  });

  return {
    metadata: {
      reportId: input.reportId,
      emailId: input.email.id,
      organizationId: input.organizationId,
      generatedAt: new Date().toISOString(),
      reportVersion: input.reportVersion,
      analysisStatus: input.email.analysisStatus,
    },
    executiveSummary: {
      riskScore,
      riskLevel,
      classification: input.email.classification,
      explanation,
    },
    emailOverview: {
      subject: input.email.subject,
      sender: input.email.senderAddress,
      recipients: input.addresses.filter((a) => a.type === 'TO').map((a) => a.address),
      replyTo: input.email.replyTo,
      returnPath: input.email.returnPath,
      date: input.email.date ? input.email.date.toISOString() : null,
      messageId: input.email.messageId,
      ingestedAt: input.email.createdAt.toISOString(),
      relayHops: input.relayHops.map((h) => ({ hopOrder: h.hopOrder, sourceIp: h.sourceIp, header: h.receivedHeader })),
    },
    authentication: {
      spf: input.spf,
      dkim: input.dkim,
      dmarc: input.dmarc ?? 'NOT_OBSERVED',
    },
    urlIntelligence: input.urls.map((u) => ({
      url: u.url,
      domain: u.domain,
      source: u.source,
      isObfuscated: u.isObfuscated,
      indicators: asStringArray(u.indicators),
    })),
    ipDomainIntelligence,
    attachments: input.attachments.map((a) => ({
      filename: a.filename,
      sha256: a.sha256,
      declaredMimeType: a.mimeType,
      actualMimeType: a.actualMimeType,
      mismatch: a.isMismatch,
      isArchive: a.isArchive,
      apkMetadata: a.apkMetadata ?? null,
      qrFindings: a.qrFindings ?? null,
      threatIndicators: asIndicatorCategories(a.threatIndicators),
    })),
    cti,
    evidenceGraphSummary: {
      urlCount: input.urls.length,
      domainCount: domainSet.size,
      ipCount: uniqueIps.length,
      attachmentCount: input.attachments.length,
      apkCount,
      qrCodeCount,
      ctiObservationCount: input.indicatorObservations.length,
      geolocatedIpCount: input.geoLocations.length,
    },
    timeline,
    riskFactors: input.riskAssessment?.factors ?? [],
    chainOfCustody: {
      attachmentHashes: input.attachments.map((a) => ({ filename: a.filename, sha256: a.sha256 })),
    },
    limitations,
  };
}
