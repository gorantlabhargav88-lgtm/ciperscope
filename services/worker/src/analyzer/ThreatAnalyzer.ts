import { PrismaClient, UrlExtractionSource } from '@ciperscope/database';
import { LocalRawEmailStore } from '@ciperscope/storage';
import { UrlExtractor } from './UrlExtractor';
import { AttachmentAnalyzer } from './AttachmentAnalyzer';
import { logger } from '@ciperscope/logger';
import { simpleParser } from 'mailparser';
import { Readable } from 'stream';

type UrlCreateData = {
  emailId: string;
  url: string;
  normalizedUrl: string | null;
  source: UrlExtractionSource;
  isObfuscated: boolean;
  indicators: string[];
};

export class ThreatAnalyzer {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly rawEmailStore: LocalRawEmailStore
  ) {}

  public async analyzeEmail(emailId: string): Promise<void> {
    const email = await this.prisma.email.findUnique({
      where: { id: emailId },
      include: {
        mimeParts: true,
        urls: true,
        attachments: true
      }
    });

    if (!email) {
      throw new Error(`Email ${emailId} not found`);
    }

    logger.info({ emailId }, 'Starting Phase 10 Threat Analysis');

    const urlsToCreate: UrlCreateData[] = [];
    
    // We only process if we have a rawStorageKey to fetch attachments from, 
    // unless MimeParts already contain inline text we can parse.
    // For now, let's assume we can fetch the full raw email to extract the text and attachments.
    // Wait, EmailForensicParser doesn't save the parsed text directly in DB, it only saves MimePart metadata.
    // So we need to re-parse or extract the specific parts.
    // To do it efficiently and safely, since mailparser streams, we can re-parse the raw stream to get text/html content
    // OR we could have saved it. Let's just re-parse the raw email using simpleParser to get the text and html bodies,
    // and process attachments.
    
    if (!email.rawStorageKey) {
       logger.warn({ emailId }, 'No rawStorageKey found for email, cannot perform threat analysis');
       return;
    }

    const rawExists = await this.rawEmailStore.exists(email.rawStorageKey);
    if (!rawExists) {
       throw new Error(`Raw email missing for analysis: ${email.rawStorageKey}`);
    }

    const stream = await this.rawEmailStore.get(email.rawStorageKey);
    const parsed = await simpleParser(stream, {
      skipHtmlToText: true,
      skipImageLinks: true,
      skipTextToHtml: true,
      skipTextLinks: true,
    });

    // 1. Analyze URLs in Text Body
    if (parsed.text) {
      const extracted = UrlExtractor.extractFromText(parsed.text);
      extracted.forEach(u => {
        urlsToCreate.push({
          emailId,
          url: u.originalObservedUrl,
          normalizedUrl: u.normalizedUrl,
          source: UrlExtractionSource.TEXT,
          isObfuscated: u.isObfuscated,
          indicators: u.indicators,
        });
      });
    }

    // 2. Analyze URLs in HTML Body
    if (parsed.html) {
      const extracted = UrlExtractor.extractFromHtml(parsed.html);
      extracted.forEach(u => {
        urlsToCreate.push({
          emailId,
          url: u.originalObservedUrl,
          normalizedUrl: u.normalizedUrl,
          source: UrlExtractionSource[u.source] || UrlExtractionSource.OTHER,
          isObfuscated: u.isObfuscated,
          indicators: u.indicators,
        });
      });
    }

    // Filter out duplicates based on originalObservedUrl within the same email
    const uniqueUrlsMap = new Map<string, UrlCreateData>();
    for (const u of urlsToCreate) {
      if (!uniqueUrlsMap.has(u.url)) {
         uniqueUrlsMap.set(u.url, u);
      }
    }
    const uniqueUrls = Array.from(uniqueUrlsMap.values());

    // 3. Analyze Attachments
    const attachmentUpdates: { id: string; data: Record<string, unknown> }[] = [];
    const newAttachments: any[] = [];
    
    if (parsed.attachments && parsed.attachments.length > 0) {
      for (const att of parsed.attachments) {
         // Create a readable stream from the attachment content (buffer)
         const attStream = Readable.from(att.content);
         
         const ext = att.filename ? att.filename.split('.').pop() : undefined;
         const declaredMime = att.contentType || 'application/octet-stream';
         
         try {
            const analysis = await AttachmentAnalyzer.analyze(attStream, declaredMime, ext);
            
            // Try to match with existing MimePart or EmailAttachment from Phase 7/8
            const existingAtt = email.attachments.find(a => a.filename === att.filename && a.sizeBytes === att.size);
            
            if (existingAtt) {
               attachmentUpdates.push({
                  id: existingAtt.id,
                  data: {
                     actualMimeType: analysis.actualMimeType,
                     isMismatch: analysis.isMismatch,
                     magicBytes: analysis.magicBytes,
                     isArchive: analysis.isArchive,
                     archiveMetadata: analysis.archiveMetadata ? JSON.parse(JSON.stringify(analysis.archiveMetadata)) : null,
                     sha256: analysis.sha256
                  }
               });
            } else {
               newAttachments.push({
                  emailId,
                  filename: att.filename || 'unknown',
                  mimeType: declaredMime,
                  sizeBytes: att.size,
                  sha256: analysis.sha256,
                  actualMimeType: analysis.actualMimeType,
                  isMismatch: analysis.isMismatch,
                  magicBytes: analysis.magicBytes,
                  isArchive: analysis.isArchive,
                  archiveMetadata: analysis.archiveMetadata ? JSON.parse(JSON.stringify(analysis.archiveMetadata)) : null
               });
            }
         } catch (e) {
            logger.error({ err: e, filename: att.filename }, 'Failed to analyze attachment');
         }
      }
    }

    // Persist all results transactionally
    await this.prisma.$transaction(async (tx) => {
       if (uniqueUrls.length > 0) {
          // Check for existing URLs to prevent unique constraint errors if any
          await tx.emailUrl.createMany({
             data: uniqueUrls
          });
       }

       if (newAttachments.length > 0) {
          await tx.emailAttachment.createMany({
             data: newAttachments
          });
       }

       for (const update of attachmentUpdates) {
          await tx.emailAttachment.update({
             where: { id: update.id },
             data: update.data
          });
       }
    });

    logger.info({ emailId, urlCount: uniqueUrls.length, attachmentCount: attachmentUpdates.length + newAttachments.length }, 'Phase 10 Threat Analysis completed');
  }
}
