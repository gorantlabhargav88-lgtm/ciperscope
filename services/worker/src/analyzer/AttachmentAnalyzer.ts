import { Readable } from 'stream';
import { fromBuffer } from 'file-type';
import * as crypto from 'crypto';
import * as yauzl from 'yauzl';
import { logger } from '@ciperscope/logger';
import { analyzeApk, ApkStaticAnalysis } from './apk/ApkAnalyzer';
import { calculateEntropy } from './AttachmentThreatIndicators';

const ZIP_LOCAL_FILE_HEADER_MAGIC = 0x04034b50;

export interface ArchiveMetadata {
  entryCount: number;
  totalUncompressedSize: number;
  hasTraversal: boolean;
  hasNestedArchive: boolean;
  suspiciousEntries: string[];
  files: string[];
  error?: string;
}

export interface AttachmentAnalysisResult {
  sha256: string | null;
  actualMimeType: string | null;
  actualExtension: string | null;
  isMismatch: boolean;
  magicBytes: string | null;
  isArchive: boolean;
  archiveMetadata: ArchiveMetadata | null;
  sizeBytes: number;
  entropy: number | null;
  apkAnalysis: ApkStaticAnalysis | null;
}

export class AttachmentAnalyzer {
  private static readonly MAGIC_BYTE_CHUNK_SIZE = 4096; // First 4KB is enough for magic bytes
  private static readonly MAX_ARCHIVE_ENTRIES = 1000;
  private static readonly MAX_UNCOMPRESSED_SIZE = 50 * 1024 * 1024; // 50MB

  public static async analyze(
    stream: Readable,
    declaredMimeType: string,
    declaredExtension?: string
  ): Promise<AttachmentAnalysisResult> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('sha256');
      let firstChunk: Buffer | null = null;
      let totalBytes = 0;
      let errorOccurred = false;

      const chunks: Buffer[] = []; // Only for archives, we need the full buffer for yauzl right now since it expects a buffer or file descriptor, though there are ways to use streams. Actually, let's just buffer it if it's small, otherwise we can't inspect zip metadata easily. Let's see if we can use yauzl.fromBuffer.
      // Wait, we can't buffer everything if it's huge. Let's just buffer up to 50MB.
      const MAX_BUFFER = 50 * 1024 * 1024;
      let fullBuffer: Buffer | null = null;
      let isBuffering = true;

      stream.on('data', (chunk: Buffer) => {
        totalBytes += chunk.length;
        hash.update(chunk);

        if (!firstChunk) {
          firstChunk = Buffer.alloc(Math.min(chunk.length, this.MAGIC_BYTE_CHUNK_SIZE));
          chunk.copy(firstChunk, 0, 0, Math.min(chunk.length, this.MAGIC_BYTE_CHUNK_SIZE));
        }

        if (isBuffering) {
          chunks.push(chunk);
          if (totalBytes > MAX_BUFFER) {
            isBuffering = false;
            // Clear chunks to save memory if it exceeds max buffer
            chunks.length = 0;
          }
        }
      });

      stream.on('error', (err) => {
        errorOccurred = true;
        reject(err);
      });

      stream.on('end', async () => {
        if (errorOccurred) return;

        const sha256 = hash.digest('hex');
        if (isBuffering) {
          fullBuffer = Buffer.concat(chunks);
        }

        let actualMimeType: string | null = null;
        let actualExtension: string | null = null;
        let magicBytesHex: string | null = null;

        if (firstChunk) {
          magicBytesHex = firstChunk.subarray(0, 8).toString('hex');
          try {
             const typeInfo = await fromBuffer(firstChunk);
             if (typeInfo) {
               actualMimeType = typeInfo.mime;
               actualExtension = typeInfo.ext;
             }
          } catch (e) {
             logger.warn({ err: e }, 'Failed to read magic bytes');
          }
        }

        // Determine mismatch
        // Note: mimeType strings can be very varied, e.g. 'application/x-zip-compressed' vs 'application/zip'
        let isMismatch = false;
        if (actualMimeType) {
          const actualBase = actualMimeType.split('/')[0].toLowerCase();
          const declaredBase = declaredMimeType.split('/')[0].toLowerCase();
          
          if (actualBase !== declaredBase) {
             // For example actual is application/x-msdownload but declared is application/pdf
             if (actualMimeType.includes('executable') || actualMimeType.includes('x-msdownload') || actualMimeType.includes('elf')) {
                // Definitely suspicious if declared was something else
                if (!declaredMimeType.includes('executable') && !declaredMimeType.includes('x-msdownload') && !declaredMimeType.includes('elf')) {
                   isMismatch = true;
                }
             }
          }
        }
        
        // Also check if declared extension contradicts actual MIME (e.g. .pdf but actual is PE)
        if (declaredExtension && actualMimeType) {
           const declExtLower = declaredExtension.toLowerCase().replace('.', '');
           if (declExtLower === 'pdf' && !actualMimeType.includes('pdf')) {
             isMismatch = true;
           }
           if (declExtLower === 'txt' && (actualMimeType.includes('executable') || actualMimeType.includes('zip'))) {
             isMismatch = true;
           }
        }

        // Detect zip structure by real magic bytes, not just file-type's mime
        // guess — APKs and other zip-based formats are still zips even when
        // `file-type` reports a more specific mime for them.
        const isZipByMagic = !!firstChunk && (firstChunk as Buffer).length >= 4 &&
          (firstChunk as Buffer).readUInt32LE(0) === ZIP_LOCAL_FILE_HEADER_MAGIC;

        let isArchive = false;
        let archiveMetadata: ArchiveMetadata | null = null;

        if ((actualMimeType === 'application/zip' || isZipByMagic) && fullBuffer) {
           isArchive = true;
           try {
             archiveMetadata = await this.inspectZipMetadata(fullBuffer);
           } catch (e: unknown) {
             const errorMsg = e instanceof Error ? e.message : 'Unknown error';
             archiveMetadata = {
               entryCount: 0, totalUncompressedSize: 0, hasTraversal: false,
               hasNestedArchive: false, suspiciousEntries: [], files: [], error: errorMsg || 'Failed to parse ZIP'
             };
           }
        }

        let apkAnalysis: ApkStaticAnalysis | null = null;
        if (isZipByMagic && fullBuffer) {
          try {
            apkAnalysis = await analyzeApk(fullBuffer);
          } catch (e: unknown) {
            logger.warn({ err: e }, 'APK analysis failed; treating attachment as a non-APK archive');
          }
        }

        const entropy = firstChunk ? calculateEntropy(firstChunk as Buffer) : null;

        resolve({
          sha256,
          actualMimeType,
          actualExtension,
          isMismatch,
          magicBytes: magicBytesHex,
          isArchive,
          archiveMetadata,
          sizeBytes: totalBytes,
          entropy,
          apkAnalysis,
        });
      });
    });
  }

  private static inspectZipMetadata(buffer: Buffer): Promise<ArchiveMetadata> {
    return new Promise((resolve, reject) => {
      let entryCount = 0;
      let totalUncompressedSize = 0;
      let hasTraversal = false;
      let hasNestedArchive = false;
      const files: string[] = [];
      const suspiciousEntries: string[] = [];

      yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
        if (err) return reject(err);
        if (!zipfile) return reject(new Error('Zipfile is undefined'));

        // Handle early exit conditions gracefully
        const stopParsing = (reason: string) => {
           zipfile.close(); // Stop parsing
           resolve({
              entryCount,
              totalUncompressedSize,
              hasTraversal,
              hasNestedArchive,
              suspiciousEntries,
              files: files.slice(0, 10), // Limit output
              error: reason
           });
        };

        zipfile.on('entry', (entry) => {
          entryCount++;
          totalUncompressedSize += entry.uncompressedSize;
          
          if (files.length < 10) {
             files.push(entry.fileName);
          }

          if (entry.fileName.includes('../') || entry.fileName.includes('..\\') || entry.fileName.startsWith('/') || entry.fileName.startsWith('\\')) {
             hasTraversal = true;
             suspiciousEntries.push(entry.fileName);
          }

          if (entry.fileName.endsWith('.zip') || entry.fileName.endsWith('.tar') || entry.fileName.endsWith('.gz')) {
             hasNestedArchive = true;
          }

          if (entryCount > this.MAX_ARCHIVE_ENTRIES) {
             return stopParsing(`Exceeded max archive entries (${this.MAX_ARCHIVE_ENTRIES})`);
          }

          if (totalUncompressedSize > this.MAX_UNCOMPRESSED_SIZE) {
             return stopParsing(`Exceeded max uncompressed size (${this.MAX_UNCOMPRESSED_SIZE} bytes) - Possible Zip Bomb`);
          }

          zipfile.readEntry();
        });

        zipfile.on('end', () => {
          resolve({
             entryCount,
             totalUncompressedSize,
             hasTraversal,
             hasNestedArchive,
             suspiciousEntries,
             files: files.slice(0, 10)
          });
        });

        zipfile.readEntry(); // Start lazy reading
      });
    });
  }
}
