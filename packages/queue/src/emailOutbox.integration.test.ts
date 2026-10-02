import { PrismaClient } from '@ciperscope/database';
import IORedis from 'ioredis';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  completeEmailOutboxEvent,
  EmailOutboxRelay,
  EmailProcessingStage,
  ensureEmailOutboxEvent,
  isEmailOutboxEventCompleted,
} from './emailOutbox';
import { QueueManager } from './index';
import { randomUUID } from 'crypto';

const databaseUrl = 'postgresql://ciperscope_user:ciperscope_password@127.0.0.1:5432/ciperscope_db?schema=public';
const prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
const queueManager = new QueueManager('redis://127.0.0.1:6379');

describe('Email dispatch outbox (real PostgreSQL and Redis)', () => {
  let organizationId: string;
  let emailId: string;
  let queueName: string;

  beforeAll(async () => {
    await prisma.$connect();
    await queueManager.getQueue('email-outbox-integration').waitUntilReady();
  });

  beforeEach(async () => {
    const organization = await prisma.organization.create({
      data: { name: 'Outbox integration', domain: `outbox-${randomUUID()}.test` },
    });
    organizationId = organization.id;
    const email = await prisma.email.create({
      data: {
        organizationId,
        sha256: randomUUID().replace(/-/g, ''),
        rawStorageKey: `${organizationId}/test.eml`,
      },
    });
    emailId = email.id;
    queueName = `email-outbox-${randomUUID()}`;
    await queueManager.getQueue(queueName).waitUntilReady();
  });

  afterAll(async () => {
    await queueManager.closeAll();
    await prisma.$disconnect();
  });

  afterEach(async () => {
    if (emailId) await prisma.email.deleteMany({ where: { id: emailId } });
    if (organizationId) await prisma.organization.deleteMany({ where: { id: organizationId } });
  });

  async function createEvent() {
    return prisma.$transaction((tx) => ensureEmailOutboxEvent(tx, {
      organizationId,
      emailId,
      stage: EmailProcessingStage.PROCESSING,
      queueName,
      jobName: 'process-email',
      payload: { organizationId, resourceId: emailId, emailId },
    }));
  }

  it('persists a dispatch intent and relays it to a deterministic BullMQ job', async () => {
    const event = await createEvent();
    const relay = new EmailOutboxRelay(prisma, queueManager);

    expect(await relay.dispatchPending()).toBe(1);

    const persisted = await prisma.emailDispatchOutbox.findUniqueOrThrow({ where: { id: event.id } });
    expect(persisted.state).toBe('DISPATCHED');
    expect(persisted.attemptCount).toBe(1);
    const job = await queueManager.getQueue(queueName).getJob(`email-outbox-${event.id}`);
    expect(job?.data.outboxEventId).toBe(event.id);

    await relay.dispatchPending();
    expect(await queueManager.getQueue(queueName).getJob(`email-outbox-${event.id}`)).toBeDefined();
    await relay.stop();
  });

  it('deduplicates repeated stage intents using the stable tenant/email/stage key', async () => {
    const first = await createEvent();
    const second = await createEvent();

    expect(second.id).toBe(first.id);
    expect(await prisma.emailDispatchOutbox.count({
      where: { organizationId, emailId, stage: EmailProcessingStage.PROCESSING },
    })).toBe(1);
  });

  it('recognizes committed stage completion without crossing tenant or email ownership', async () => {
    const event = await createEvent();
    await prisma.emailDispatchOutbox.update({
      where: { id: event.id },
      data: { state: 'COMPLETED' },
    });

    expect(await isEmailOutboxEventCompleted(prisma, event.id, organizationId, emailId)).toBe(true);
    expect(await isEmailOutboxEventCompleted(prisma, event.id, 'another-tenant', emailId)).toBe(false);
    expect(await isEmailOutboxEventCompleted(prisma, event.id, organizationId, 'another-email')).toBe(false);
    expect(await isEmailOutboxEventCompleted(prisma, undefined, organizationId, emailId)).toBe(false);
  });

  it('prunes only old completed events for completed emails in bounded batches', async () => {
    const event = await createEvent();
    await prisma.$transaction([
      prisma.email.update({ where: { id: emailId }, data: { analysisStatus: 'COMPLETED' } }),
      prisma.emailDispatchOutbox.update({
        where: { id: event.id },
        data: { state: 'COMPLETED', updatedAt: new Date(Date.now() - 91 * 24 * 60 * 60 * 1000) },
      }),
    ]);
    const relay = new EmailOutboxRelay(prisma, queueManager, { cleanupBatchSize: 1 });

    expect(await relay.dispatchPending()).toBe(0);
    expect(await prisma.emailDispatchOutbox.findUnique({ where: { id: event.id } })).toBeNull();
    await relay.stop();
  });

  it('keeps failed Redis dispatch pending and recovers when Redis is available', async () => {
    const event = await createEvent();
    const unavailableQueue = new QueueManager('redis://127.0.0.1:1');
    const failingRelay = new EmailOutboxRelay(prisma, unavailableQueue, {
      dispatchTimeoutMs: 200,
      retryBaseDelayMs: 1,
    });

    expect(await failingRelay.dispatchPending()).toBe(0);
    const pending = await prisma.emailDispatchOutbox.findUniqueOrThrow({ where: { id: event.id } });
    expect(pending.state).toBe('PENDING');
    expect(pending.attemptCount).toBe(1);
    expect(pending.lastError).toBeTruthy();
    await failingRelay.stop();
    await unavailableQueue.closeAll();

    await prisma.emailDispatchOutbox.update({
      where: { id: event.id },
      data: { nextAttemptAt: new Date(0) },
    });
    const recoveryRelay = new EmailOutboxRelay(prisma, queueManager);
    expect(await recoveryRelay.dispatchPending()).toBe(1);
    expect((await prisma.emailDispatchOutbox.findUniqueOrThrow({ where: { id: event.id } })).state)
      .toBe('DISPATCHED');
    expect(await queueManager.getQueue(queueName).getJob(`email-outbox-${event.id}`)).toBeDefined();
    await recoveryRelay.stop();
  });

  it('recovers the add-succeeded/database-update-crashed window without adding a second job', async () => {
    const event = await createEvent();
    const queue = queueManager.getQueue(queueName);
    await queue.add(event.jobName, event.payload as object, { jobId: `email-outbox-${event.id}` });

    const relay = new EmailOutboxRelay(prisma, queueManager);
    expect(await relay.dispatchPending()).toBe(1);
    expect(await queue.getJob(`email-outbox-${event.id}`)).toBeDefined();
    expect(await queue.getJobCountByTypes('waiting', 'active', 'completed', 'failed')).toBe(1);
    await relay.stop();
  });

  it('allows only one of concurrent relays to claim an event', async () => {
    const event = await createEvent();
    const firstRelay = new EmailOutboxRelay(prisma, queueManager);
    const secondRelay = new EmailOutboxRelay(prisma, queueManager);

    const dispatchCounts = await Promise.all([
      firstRelay.dispatchPending(),
      secondRelay.dispatchPending(),
    ]);

    expect(dispatchCounts.reduce((sum, count) => sum + count, 0)).toBe(1);
    expect(await queueManager.getQueue(queueName).getJobCountByTypes('waiting', 'active', 'completed', 'failed'))
      .toBe(1);
    await firstRelay.stop();
    await secondRelay.stop();
    expect((await prisma.emailDispatchOutbox.findUniqueOrThrow({ where: { id: event.id } })).state)
      .toBe('DISPATCHED');
  });

  it('retries a failed worker job and completes the outbox event on success', async () => {
    const event = await createEvent();
    let attempts = 0;
    let resolveCompleted!: () => void;
    let rejectCompleted!: (error: Error) => void;
    const completed = new Promise<void>((resolve, reject) => {
      resolveCompleted = resolve;
      rejectCompleted = reject;
    });
    const worker = queueManager.createWorker(queueName, async () => {
      attempts++;
      if (attempts === 1) throw new Error('test worker failure');
      await prisma.$transaction((tx) => completeEmailOutboxEvent(tx, event.id));
      return { success: true };
    });
    worker.once('completed', resolveCompleted);
    worker.once('error', rejectCompleted);
    await worker.waitUntilReady();

    const relay = new EmailOutboxRelay(prisma, queueManager);
    expect(await relay.dispatchPending()).toBe(1);
    await Promise.race([
      completed,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('worker retry timed out')), 20_000)),
    ]);

    expect(attempts).toBe(2);
    expect((await prisma.emailDispatchOutbox.findUniqueOrThrow({ where: { id: event.id } })).state)
      .toBe('COMPLETED');
    await relay.stop();
  });

  it('rejects an outbox record whose tenant does not own the email', async () => {
    const otherOrganization = await prisma.organization.create({
      data: { name: 'Other tenant', domain: `other-${randomUUID()}.test` },
    });

    await expect(prisma.$transaction((tx) => ensureEmailOutboxEvent(tx, {
      organizationId: otherOrganization.id,
      emailId,
      stage: EmailProcessingStage.PROCESSING,
      queueName,
      jobName: 'process-email',
      payload: { organizationId: otherOrganization.id, resourceId: emailId },
    }))).rejects.toThrow();

    await prisma.organization.delete({ where: { id: otherOrganization.id } });
  });
});
