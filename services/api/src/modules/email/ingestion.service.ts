import { PrismaClient, EmailClassification, Prisma } from '@ciperscope/database';
import { RawEmailStore } from '@ciperscope/storage';
import {
  ensureEmailOutboxEvent,
  EmailProcessingStage,
} from '@ciperscope/queue';
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
    private storage: RawEmailStore
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
        if (existingEmail.analysisStatus !== 'COMPLETED' && existingEmail.rawStorageKey) {
          await this.ensureInitialDispatch(existingEmail, organizationId, requestId, traceId, userId);
        }
        return { emailId: existingEmail.id, status: existingEmail.analysisStatus, duplicate: true };
      }

      // 3. Store raw bytes. Database uniqueness serializes concurrent
      // tenant/hash ingestions; Redis is not required for durable ingestion.
      const storageKey = `${organizationId}/${rawSha256}.eml`;
      await this.storage.put(storageKey, fs.createReadStream(tempFilePath));

      try {
        // 4. Persist the Email and its dispatch intent atomically.
        const email = await this.prisma.$transaction(async (tx) => {
          const createdEmail = await tx.email.create({
            data: {
              organizationId,
              ingestionSrc: source,
              rawStorageKey: storageKey,
              sha256: rawSha256,
              classification: EmailClassification.UNKNOWN,
            },
          });
          await ensureEmailOutboxEvent(tx, {
            organizationId,
            emailId: createdEmail.id,
            stage: EmailProcessingStage.PROCESSING,
            queueName: 'email-processing',
            jobName: 'process-email',
            payload: {
              organizationId,
              resourceId: createdEmail.id,
              jobId: `ingest-${createdEmail.id}`,
              emailId: createdEmail.id,
              operation: 'ingest',
              ...(userId ? { actorId: userId } : {}),
              ...(requestId ? { requestId } : {}),
              ...(traceId ? { traceId } : {}),
              storageReference: storageKey,
              rawSha256,
              source,
            },
          });
          return createdEmail;
        });

        return { emailId: email.id, status: email.analysisStatus, duplicate: false };
      } catch (error) {
        if (
          error instanceof Prisma.PrismaClientKnownRequestError &&
          error.code === 'P2002'
        ) {
          const concurrentEmail = await this.prisma.email.findUnique({
            where: { organizationId_sha256: { organizationId, sha256: rawSha256 } },
          });
          if (concurrentEmail) {
            if (concurrentEmail.analysisStatus !== 'COMPLETED' && concurrentEmail.rawStorageKey) {
              await this.ensureInitialDispatch(
                concurrentEmail,
                organizationId,
                requestId,
                traceId,
                userId
              );
            }
            return {
              emailId: concurrentEmail.id,
              status: concurrentEmail.analysisStatus,
              duplicate: true,
            };
          }
        }
        throw error;
      }
    } finally {
      // Always cleanup temp file
      if (fs.existsSync(tempFilePath)) {
        await fs.promises.unlink(tempFilePath).catch(() => {});
      }
    }
  }

  private async ensureInitialDispatch(
    email: { id: string; rawStorageKey: string | null; sha256: string; ingestionSrc: string },
    organizationId: string,
    requestId?: string,
    traceId?: string,
    userId?: string
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      await ensureEmailOutboxEvent(tx, {
        organizationId,
        emailId: email.id,
        stage: EmailProcessingStage.PROCESSING,
        queueName: 'email-processing',
        jobName: 'process-email',
        payload: {
          organizationId,
          resourceId: email.id,
          jobId: `ingest-${email.id}`,
          emailId: email.id,
          operation: 'ingest',
          ...(userId ? { actorId: userId } : {}),
          ...(requestId ? { requestId } : {}),
          ...(traceId ? { traceId } : {}),
          storageReference: email.rawStorageKey!,
          rawSha256: email.sha256,
          source: email.ingestionSrc,
        },
      });
    });
  }
}
