import { describe, it, expect, afterAll } from 'vitest';
import { notificationHub } from '../notificationHub';
import type { NotificationEvent } from '@ciperscope/queue';

/**
 * Real Redis pub/sub roundtrip (not mocked) — proves the actual mechanism
 * the SSE route (GET /alerts/stream) writes to the HTTP response: publish
 * → subscribeOrg's listener fires. Ref-counting and unsubscribe behavior
 * (multiple concurrent "connections" for the same org, and org isolation)
 * are the two properties the real-time notification system depends on
 * most for correctness under concurrent SSE clients.
 */
describe('notificationHub (real Redis pub/sub)', () => {
  it('a published event is delivered to a subscriber of the same organization', async () => {
    const orgId = `org-${Date.now()}-a`;
    const unsubscribe = await notificationHub.subscribeOrg(orgId, () => {});
    await unsubscribe();

    const received: NotificationEvent[] = [];
    const realUnsubscribe = await notificationHub.subscribeOrg(orgId, (event) => received.push(event));

    await notificationHub.publish({ type: 'ALERT_CREATED', organizationId: orgId, alertId: 'a1', severity: 'CRITICAL', timestamp: new Date().toISOString() });

    // give Redis pub/sub a moment to deliver — real network round trip, not fake timers
    await new Promise((r) => setTimeout(r, 300));

    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ type: 'ALERT_CREATED', organizationId: orgId, alertId: 'a1' });

    await realUnsubscribe();
  });

  it('a subscriber for a DIFFERENT organization never receives another org\'s event (tenant isolation of the pub/sub channel itself)', async () => {
    const orgA = `org-${Date.now()}-iso-a`;
    const orgB = `org-${Date.now()}-iso-b`;
    const receivedA: NotificationEvent[] = [];
    const receivedB: NotificationEvent[] = [];

    const unsubA = await notificationHub.subscribeOrg(orgA, (e) => receivedA.push(e));
    const unsubB = await notificationHub.subscribeOrg(orgB, (e) => receivedB.push(e));

    await notificationHub.publish({ type: 'ALERT_CREATED', organizationId: orgA, alertId: 'x', timestamp: new Date().toISOString() });
    await new Promise((r) => setTimeout(r, 300));

    expect(receivedA).toHaveLength(1);
    expect(receivedB).toHaveLength(0);

    await unsubA();
    await unsubB();
  });

  it('two concurrent subscribers for the same org (simulating two browser tabs) BOTH receive the event exactly once — no duplication, no missed delivery', async () => {
    const orgId = `org-${Date.now()}-multi`;
    const receivedX: NotificationEvent[] = [];
    const receivedY: NotificationEvent[] = [];

    const unsubX = await notificationHub.subscribeOrg(orgId, (e) => receivedX.push(e));
    const unsubY = await notificationHub.subscribeOrg(orgId, (e) => receivedY.push(e));

    await notificationHub.publish({ type: 'ALERT_CREATED', organizationId: orgId, alertId: 'dup-check', timestamp: new Date().toISOString() });
    await new Promise((r) => setTimeout(r, 300));

    expect(receivedX).toHaveLength(1);
    expect(receivedY).toHaveLength(1);

    // Unsubscribing one listener must not affect the other (ref-counting,
    // not a blunt org-wide unsubscribe).
    await unsubX();
    await notificationHub.publish({ type: 'ALERT_CREATED', organizationId: orgId, alertId: 'after-partial-unsub', timestamp: new Date().toISOString() });
    await new Promise((r) => setTimeout(r, 300));

    expect(receivedX).toHaveLength(1); // unchanged
    expect(receivedY).toHaveLength(2); // still subscribed

    await unsubY();
  });

  it('after the last subscriber for an org unsubscribes, a later publish delivers to no one and does not throw', async () => {
    const orgId = `org-${Date.now()}-cleanup`;
    const received: NotificationEvent[] = [];
    const unsub = await notificationHub.subscribeOrg(orgId, (e) => received.push(e));
    await unsub();

    await expect(notificationHub.publish({ type: 'ALERT_CREATED', organizationId: orgId, timestamp: new Date().toISOString() })).resolves.not.toThrow();
    await new Promise((r) => setTimeout(r, 200));
    expect(received).toHaveLength(0);
  });

  it('unsubscribe is idempotent — calling it twice never throws', async () => {
    const orgId = `org-${Date.now()}-idempotent`;
    const unsub = await notificationHub.subscribeOrg(orgId, () => {});
    await unsub();
    await expect(unsub()).resolves.not.toThrow();
  });
});
