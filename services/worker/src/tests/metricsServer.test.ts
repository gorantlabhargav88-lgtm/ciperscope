import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createMetricsServer } from '../metricsServer';
import { register } from '@platformatic/prom-client';

describe('Worker Metrics Server', () => {
  beforeEach(() => {
    register.clear();
  });
  afterEach(() => {
    register.clear();
  });
  it('should return 200 OK for /health', async () => {
    const server = createMetricsServer();
    const response = await server.inject({
      method: 'GET',
      url: '/health'
    });

    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ status: 'ok' });
  });

  it('should return metrics at /metrics', async () => {
    const server = createMetricsServer();
    const response = await server.inject({
      method: 'GET',
      url: '/metrics'
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).toContain('process_cpu_user_seconds_total'); // Default prometheus metric
  });
});
