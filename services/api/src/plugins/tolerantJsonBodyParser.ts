import fp from 'fastify-plugin';
import { FastifyInstance, FastifyError } from 'fastify';

/**
 * Fastify 5's default JSON body parser rejects a request that declares
 * `Content-Type: application/json` but sends an empty body
 * (FST_ERR_CTP_EMPTY_JSON_BODY) — a real, previously-undetected regression
 * from the Fastify 4→5 migration: every body-less POST (logout, webhook
 * test-delivery, etc.) returned 500 for any real client that sets
 * Content-Type unconditionally, because fastify.inject()-based tests never
 * set that header on a body-less request and so never observed it. An
 * empty body on a JSON route is treated as `undefined` (schema `required`
 * fields still reject it exactly as before); a non-empty body is parsed
 * with the same strictness Fastify's own default parser uses.
 */
export default fp(async (fastify: FastifyInstance) => {
  fastify.addContentTypeParser('application/json', { parseAs: 'string' }, (_req, body, done) => {
    if (body === '' || body === undefined) {
      done(null, undefined);
      return;
    }
    try {
      done(null, JSON.parse(body as string));
    } catch (err) {
      (err as FastifyError).statusCode = 400;
      done(err as Error, undefined);
    }
  });
});
