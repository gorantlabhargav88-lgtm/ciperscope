import { EventEmitter } from 'events';
import { env } from '@ciperscope/config';
import { logger } from '@ciperscope/logger';
import { createRedisConnection, notificationChannelFor, publishNotification, type NotificationEvent } from '@ciperscope/queue';

/**
 * Fan-out hub for the real-time notification bell: one Redis SUBSCRIBE
 * connection shared by every SSE client this API process holds open,
 * ref-counted per organization channel so N concurrent browser tabs for
 * the same org only ever cost one Redis subscription. A Redis connection
 * that has ever called SUBSCRIBE can no longer run ordinary commands, so
 * publishing (used by this API process for INVITATION_ACCEPTED — Worker's
 * FusionEngine/gmail-sync publish their own ALERT_CREATED events directly,
 * see packages/queue/src/notificationChannel.ts) goes through a second,
 * separate connection — both built with the same createRedisConnection()
 * this codebase already uses everywhere else, never a new abstraction.
 */
class NotificationHub {
  private readonly subscriber = createRedisConnection(env.REDIS_URL);
  private readonly publisher = createRedisConnection(env.REDIS_URL);
  private readonly emitter = new EventEmitter();
  private readonly refCounts = new Map<string, number>();

  constructor() {
    this.emitter.setMaxListeners(0);
    this.subscriber.on('message', (channel: string, message: string) => {
      this.emitter.emit(channel, message);
    });
    this.subscriber.on('error', (err) => logger.warn({ err }, 'Notification hub Redis subscriber error'));
    this.publisher.on('error', (err) => logger.warn({ err }, 'Notification hub Redis publisher error'));
  }

  async publish(event: NotificationEvent): Promise<void> {
    await publishNotification(this.publisher, event);
  }

  /** Returns an unsubscribe function the caller MUST invoke exactly once (on SSE connection close). */
  async subscribeOrg(organizationId: string, listener: (event: NotificationEvent) => void): Promise<() => Promise<void>> {
    const channel = notificationChannelFor(organizationId);
    const count = this.refCounts.get(channel) ?? 0;
    if (count === 0) {
      await this.subscriber.subscribe(channel);
    }
    this.refCounts.set(channel, count + 1);

    const wrapped = (message: string) => {
      try {
        listener(JSON.parse(message) as NotificationEvent);
      } catch {
        // malformed payload — never crash the SSE connection over it
      }
    };
    this.emitter.on(channel, wrapped);

    let unsubscribed = false;
    return async () => {
      if (unsubscribed) return; // idempotent — a client disconnect can race with server shutdown
      unsubscribed = true;
      this.emitter.off(channel, wrapped);
      const remaining = (this.refCounts.get(channel) ?? 1) - 1;
      if (remaining <= 0) {
        this.refCounts.delete(channel);
        try {
          await this.subscriber.unsubscribe(channel);
        } catch {
          // connection may already be closing (process shutdown) — safe to ignore
        }
      } else {
        this.refCounts.set(channel, remaining);
      }
    };
  }
}

export const notificationHub = new NotificationHub();
