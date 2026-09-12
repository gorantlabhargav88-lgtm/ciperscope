import { PrismaClient, EmailClassification } from '@ciperscope/database';
import { RawEmailStore } from '@ciperscope/storage';
import { QueueManager, IdempotencyManager } from '@ciperscope/queue';
import { logger } from '@ciperscope/logger';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { pipeline } from 'stream/promises';
import { Transform } from 'stream';

export interface IngestionOptions {
  organizationId: string;
  source: string;
  traceId?: string;
  requestId?: string;
  userId?: string;
}

export class EmailIngestionService {
  constructor(
    private prisma: PrismaClient,
    private storage: RawEmailStore,
    private idempotencyManager: IdempotencyManager,
    private queueManager: QueueManager
  ) {}

  /**
   * Processes a streaming file upload for an email.
   */
  async ingestFromStream(
    stream: NodeJS.ReadableStream,
    options: IngestionOptions
  ): Promise<{ emailId: string; status: string; duplicate: boolean }> {
    const { organizationId, source, traceId, requestId, userId } = options;

    // 1. Stream to temporary file and calculate SHA-256 simultaneously
    const tempFilePath = path.join(os.tmpdir(), `ciperscope-ingest-${crypto.randomUUID()}.eml`);
    const hash = crypto.createHash('sha256');
    let sizeBytes = 0;

    const hashStream = new Transform({
      transform(chunk: Buffer, _encoding: string, callback: () => void) {
        hash.update(chunk);
        sizeBytes += chunk.length;
        this.push(chunk);
        callback();
      }
    });

    try {
      await pipeline(
        stream,
        hashStream,
        fs.createWriteStream(tempFilePath)
      );

      if ((stream as NodeJS.ReadableStream & { truncated?: boolean }).truncated) {
        throw new Error('File size limit reached');
      }

      const rawSha256 = hash.digest('hex');

      logger.info({ organizationId, rawSha256, sizeBytes, traceId }, 'Stream processed and hashed');

      if (sizeBytes === 0) {
        throw new Error('Empty file uploaded');
      }

      // 2. Tenant-scoped deduplication
      const existingEmail = await this.prisma.email.findUnique({
        where: {
          organizationId_sha256: {
            organizationId,
            sha256: rawSha256,
          }
        }
      });

      if (existingEmail) {
        logger.info({ emailId: existingEmail.id, rawSha256 }, 'Duplicate email detected');
        return { emailId: existingEmail.id, status: existingEmail.ingestionSrc, duplicate: true };
      }

      // 3. Durable Idempotency Integration
      // In this case, idempotency operationKey can be the SHA256 of the payload.
      const operationKey = `ingest-${rawSha256}`;
      // Use a dummy resourceId 'email' until we generate the actual ID.
      const locked = await this.idempotencyManager.acquireLock(organizationId, operationKey, 'email', 'INGEST_EMAIL');
      
      if (!locked) {
        // Another process is currently handling this exact email hash. 
        // We will consider it a duplicate to be safe, or we could wait. For now, fail or return duplicate.
        throw new Error('Concurrent ingestion detected for the same email hash. Please retry if it fails.');
      }

      try {
        // 4. Store raw bytes
        const storageKey = `${organizationId}/${rawSha256}.eml`;
        const readStream = fs.createReadStream(tempFilePath);
        
        await this.storage.put(storageKey, readStream);

        // 5. Database Persistence
        const email = await this.prisma.email.create({
          data: {
            organizationId,
            ingestionSrc: source,
            rawStorageKey: storageKey,
            sha256: rawSha256,
            classification: EmailClassification.UNKNOWN,
            // Additional extraction happens in the worker
          }
        });
        // 6. Enqueue BullMQ job
        const queue = this.queueManager.getQueue('email-processing');
        await queue.add('process-email', {
          organizationId,
          resourceId: email.id,
          emailId: email.id,
          jobId: email.id, // Or unique job id
          operation: 'PROCESS_EMAIL',
          actorId: userId,
          requestId,
          traceId,
          storageReference: storageKey,
          rawSha256,
          source
        });

        // Mark idempotent op complete
        await this.idempotencyManager.markCompleted(organizationId, operationKey, 'email', email.id);

        return { emailId: email.id, status: 'RECEIVED', duplicate: false };
      } catch (err: unknown) {
        await this.idempotencyManager.markFailed(organizationId, operationKey, 'email', err instanceof Error ? err.message : String(err));
        throw err;
      }
    } finally {
      // Always cleanup temp file
      if (fs.existsSync(tempFilePath)) {
        await fs.promises.unlink(tempFilePath).catch(() => {});
      }
    }
  }
}
