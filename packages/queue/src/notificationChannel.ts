import IORedis from 'ioredis';

/**
 * Real-time notification transport: Worker/API process creates a domain
 * event (an Alert row) → publishes here over the SAME Redis instance
 * already used for BullMQ (createRedisConnection, this package) → the API
 * process's SSE endpoint (services/api/src/modules/alert/alert.routes.ts's
 * GET /alerts/stream) is subscribed and relays it to connected browsers.
 * No second Redis client abstraction, no new infrastructure — this is a
 * few lines of pub/sub over the existing ioredis connection.
 */
export const NOTIFICATION_CHANNEL_PREFIX = 'notifications:org:';

export function notificationChannelFor(organizationId: string): string {
  return `${NOTIFICATION_CHANNEL_PREFIX}${organizationId}`;
}

export type NotificationEventType =
  | 'ALERT_CREATED'
  | 'INVITATION_ACCEPTED';

export interface NotificationEvent {
  type: NotificationEventType;
  organizationId: string;
  alertId?: string;
  userId?: string;
  severity?: string;
  title?: string;
  timestamp: string;
}

/**
 * Fire-and-forget: a publish failure (Redis briefly unavailable) must
 * never fail the caller's real work (the Alert row is already durably
 * persisted before this is ever called) — same "never let a notification
 * side-channel fail the primary operation" policy already used for the
 * webhook notifier in services/worker/src/analyzer/FusionEngine.ts.
 */
export async function publishNotification(redis: IORedis, event: NotificationEvent): Promise<void> {
  try {
    await redis.publish(notificationChannelFor(event.organizationId), JSON.stringify(event));
  } catch {
    // swallowed — see doc comment above
  }
}
