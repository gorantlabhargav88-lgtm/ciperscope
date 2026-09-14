import { PrismaClient } from '@ciperscope/database';
import { logger } from '@ciperscope/logger';
import { env } from '@ciperscope/config';
import { EmailForensicParser } from '../parser/EmailForensicParser';
import { RawEmailStore } from '@ciperscope/storage';

interface MLServiceResponse {
  status: string;
  predictedLabel: string | null;
  modelScore: number | null;
  modelName: string | null;
  modelVersion: string | null;
  artifactSha256: string | null;
  tokenizerVersion: string | null;
  preprocessingVersion: string | null;
  inferenceTimestamp: string | null;
  serviceVersion: string | null;
}

export class MLClassifier {
  constructor(
    private prisma: PrismaClient,
    private rawEmailStore: RawEmailStore,
    private mlServiceUrl: string = env.ML_SERVICE_URL || 'http://ml-worker:8000',
    private mlServiceToken: string = env.ML_SERVICE_TOKEN || 'internal-secret-token'
  ) {}

  public async classifyEmail(emailId: string): Promise<void> {
    logger.info({ emailId }, 'Starting ML Classification for email');

    const email = await this.prisma.email.findUnique({
      where: { id: emailId },
      include: {
        headers: true,
        addresses: true
      }
    });

    if (!email) {
      throw new Error(`Email ${emailId} not found`);
    }

    // Prepare inputs deterministically
    const subject = email.headers.find(h => h.name.toLowerCase() === 'subject')?.value || '';
    const sender = email.addresses.find(a => a.headerName.toLowerCase() === 'from')?.address || '';
    const replyTo = email.addresses.find(a => a.headerName.toLowerCase() === 'reply-to')?.address || '';

    // Getting text from raw store to be perfectly deterministic and not rely on parsed DB if not needed.
    // However, Phase 10 extracted text might be better. Let's just use the LocalRawEmailStore and parse simple text.
    const rawStream = await this.rawEmailStore.get(email.rawStorageKey!);
    const parsed = await EmailForensicParser.parse(rawStream);

    // Find a text part
    const textPart = parsed.mimeParts.find(m => m.contentType.includes('text/plain'));
    const body = textPart?.filename || '';

    // For simplicity, we just pass the subject, sender, replyTo.
    const modelInputText = `SUBJECT:\n${subject}\n\nFROM:\n${sender}\n\nREPLY-TO:\n${replyTo}\n\nBODY:\n${body}`;

    const requestPayload = {
      requestId: `ml-${emailId}-${Date.now()}`,
      emailId: email.id,
      organizationId: email.organizationId,
      modelInputText,
      preprocessingVersion: '1.0',
      requestedModelVersion: 'latest'
    };

    let mlResponse: MLServiceResponse;

    try {
      // NOTE: Using native fetch
      const res = await fetch(`${this.mlServiceUrl}/api/v1/predict`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.mlServiceToken}`
        },
        body: JSON.stringify(requestPayload)
      });

      if (!res.ok) {
        if (res.status === 408 || res.status === 504) {
          throw new Error('TIMEOUT');
        }
        throw new Error(`ML Service returned HTTP ${res.status}`);
      }

      mlResponse = (await res.json()) as MLServiceResponse;
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      logger.error({ err, emailId }, 'ML Classification request failed');
      const status = errorMsg === 'TIMEOUT' ? 'TIMEOUT' : 'FAILED';

      await this.prisma.mLInference.create({
        data: {
          organizationId: email.organizationId,
          emailId: email.id,
          status,
          explanation: errorMsg
        }
      });
      return;
    }

    await this.prisma.mLInference.create({
      data: {
        organizationId: email.organizationId,
        emailId: email.id,
        status: mlResponse.status,
        prediction: mlResponse.predictedLabel,
        modelScore: mlResponse.modelScore,
        modelName: mlResponse.modelName,
        modelVersion: mlResponse.modelVersion,
        artifactSha256: mlResponse.artifactSha256,
        tokenizerVersion: mlResponse.tokenizerVersion,
        preprocessingVersion: mlResponse.preprocessingVersion,
        labelMappingVersion: '1.0',
        serviceVersion: mlResponse.serviceVersion,
      }
    });

    logger.info({ emailId, status: mlResponse.status }, 'ML Classification completed');
  }
}
