import { simpleParser, ParsedMail, HeaderValue } from 'mailparser';
import { Readable } from 'stream';

export interface ParsedEmailForensics {
  headers: Array<{ name: string; value: string; index: number }>;
  addresses: Array<{ headerName: string; displayName?: string; address?: string; localPart?: string; domain?: string; raw: string }>;
  relayHops: Array<{
    hopOrder: number;
    receivingHost?: string;
    sendingHost?: string;
    fromHost?: string;
    byHost?: string;
    protocol?: string;
    parsedConfidence?: number;
    sourceIp?: string;
    hostname?: string;
    timestamp?: Date;
    receivedHeader: string;
  }>;
  mimeParts: Array<{
    partIndex: string;
    contentType: string;
    contentDisposition?: string;
    filename?: string;
    contentId?: string;
    contentLocation?: string;
    transferEncoding?: string;
    charset?: string;
    sizeBytes?: number;
    isAttachment: boolean;
  }>;
}

export class EmailForensicParser {
  /**
   * Parses the raw email stream ensuring strict safety limits.
   * No network activity is permitted.
   */
  static async parse(stream: Readable): Promise<ParsedEmailForensics> {
    const parsed: ParsedMail = await simpleParser(stream, {
      skipHtmlToText: true,
      skipImageLinks: true, // Prevents fetching images
      skipTextToHtml: true,
      skipTextLinks: true,
    });

    const MAX_HEADER_COUNT = 1000;
    const MAX_FIELD_LENGTH = 32768; // 32KB
    const MAX_MIME_PARTS = 200;
    const MAX_RELAY_HOPS = 100;

    const enforceStringLimit = (val: string) => {
      if (val.length > MAX_FIELD_LENGTH) {
        throw new Error(`Field length exceeds maximum limit of ${MAX_FIELD_LENGTH} bytes`);
      }
      return val;
    };

    const headers: ParsedEmailForensics['headers'] = [];
    let headerIndex = 0;

    const addresses: ParsedEmailForensics['addresses'] = [];
    const relayHops: ParsedEmailForensics['relayHops'] = [];

    // Parse Headers
    // mailparser exposes headers as a Map where keys are lowercased
    // values can be string, Date, AddressObject, or an Array of these.
    parsed.headers.forEach((value, key) => {
      const processHeaderValue = (val: HeaderValue) => {
        let rawStr = '';
        if (typeof val === 'string') {
          rawStr = val;
        } else if (val instanceof Date) {
          rawStr = val.toISOString();
        } else if (typeof val === 'object') {
          if ('value' in val && Array.isArray(val.value)) {
            // Address object
            const addressObjects = val.value;
            // AddressObject has a .text property for the raw string representation
            rawStr = (val as import('mailparser').AddressObject).text || '';
            addressObjects.forEach(addr => {
              const localPart = addr.address ? addr.address.split('@')[0] : undefined;
              const domain = addr.address ? addr.address.split('@')[1] : undefined;
              addresses.push({
                headerName: key,
                displayName: addr.name || undefined,
                address: addr.address || undefined,
                localPart,
                domain,
                raw: rawStr
              });
            });
          } else {
             // Other structured headers like content-type
             rawStr = (val as { value?: string }).value || JSON.stringify(val);
          }
        }

        if (headerIndex >= MAX_HEADER_COUNT) {
          throw new Error(`Header count exceeds maximum limit of ${MAX_HEADER_COUNT}`);
        }
        
        headers.push({ 
          name: enforceStringLimit(key), 
          value: enforceStringLimit(rawStr), 
          index: headerIndex++ 
        });
      };

      if (Array.isArray(value)) {
        value.forEach(processHeaderValue);
      } else {
        processHeaderValue(value as HeaderValue);
      }
    });

    // Extract Received Hops
    // Received headers are stored in an array by mailparser usually.
    const receivedHeaders = parsed.headers.get('received');
    if (receivedHeaders) {
      const receivedArray = Array.isArray(receivedHeaders) ? receivedHeaders : [receivedHeaders];
      receivedArray.forEach((rec, idx) => {
        let rawStr = '';
        if (typeof rec === 'string') {
          rawStr = rec;
        } else if (typeof rec === 'object' && rec !== null && 'value' in rec) {
           rawStr = (rec as { value?: string }).value || String(rec);
        } else {
           rawStr = String(rec);
        }

        // Basic Regex parsing for Received hops
        const fromMatch = rawStr.match(/from\s+([^\s]+)(?:\s*\([^)]*\[([a-fA-F0-9.:]+)\][^)]*\))?/i);
        const byMatch = rawStr.match(/by\s+([^\s]+)/i);
        const withMatch = rawStr.match(/with\s+([^\s;]+)/i);
        
        let timestamp: Date | undefined;
        const dateMatch = rawStr.match(/;\s*(.+)$/);
        if (dateMatch && dateMatch[1]) {
           const parsedDate = new Date(dateMatch[1]);
           if (!isNaN(parsedDate.getTime())) {
             timestamp = parsedDate;
           }
        }

        if (relayHops.length >= MAX_RELAY_HOPS) {
          throw new Error(`Relay hops count exceeds maximum limit of ${MAX_RELAY_HOPS}`);
        }

        relayHops.push({
          hopOrder: idx,
          receivedHeader: enforceStringLimit(rawStr),
          fromHost: fromMatch ? enforceStringLimit(fromMatch[1]) : undefined,
          sourceIp: fromMatch && fromMatch[2] ? enforceStringLimit(fromMatch[2]) : undefined,
          byHost: byMatch ? enforceStringLimit(byMatch[1]) : undefined,
          protocol: withMatch ? enforceStringLimit(withMatch[1]) : undefined,
          timestamp,
          parsedConfidence: fromMatch || byMatch ? 0.8 : 0.2
        });
      });
    }

    // Build MIME Parts Tree
    const mimeParts: ParsedEmailForensics['mimeParts'] = [];
    
    // mailparser flattens attachments but we can extract them.
    // To build a true tree, we would need to hook into the stream events, 
    // but for Phase 8, treating body & attachments as top-level parts is a safe approximation.
    
    let partIdx = 1;
    if (parsed.text) {
      mimeParts.push({
        partIndex: String(partIdx++),
        contentType: 'text/plain',
        sizeBytes: Buffer.byteLength(parsed.text),
        isAttachment: false
      });
    }
    
    if (parsed.html) {
      mimeParts.push({
        partIndex: String(partIdx++),
        contentType: 'text/html',
        sizeBytes: Buffer.byteLength(parsed.html),
        isAttachment: false
      });
    }

    if (parsed.attachments) {
      parsed.attachments.forEach(att => {
        mimeParts.push({
          partIndex: String(partIdx++),
          contentType: att.contentType ? enforceStringLimit(att.contentType) : '',
          contentDisposition: att.contentDisposition ? enforceStringLimit(att.contentDisposition) : undefined,
          filename: att.filename ? enforceStringLimit(att.filename) : undefined,
          contentId: att.contentId ? enforceStringLimit(att.contentId) : undefined,
          sizeBytes: att.size,
          isAttachment: true
        });
      });
    }

    if (mimeParts.length > MAX_MIME_PARTS) {
      throw new Error(`MIME parts count exceeds maximum limit of ${MAX_MIME_PARTS}`);
    }

    return {
      headers,
      addresses,
      relayHops,
      mimeParts
    };
  }
}
