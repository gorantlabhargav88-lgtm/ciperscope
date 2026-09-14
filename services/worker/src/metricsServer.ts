import Fastify from 'fastify';
import fastifyMetrics from 'fastify-metrics';

export function createMetricsServer() {
  const server = Fastify();

  server.register(fastifyMetrics, { endpoint: '/metrics' });

  server.get('/health', async () => {
    return { status: 'ok' };
  });

  return server;
}
