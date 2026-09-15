import { z } from 'zod';
import zodToJsonSchema from 'zod-to-json-schema';

// Centralized UUID validation for all IDs
export const uuidSchema = z.string().uuid('Invalid UUID format');

// Parameters for typical single-email routes
export const EmailParamsSchema = z.object({
  emailId: uuidSchema,
});

// Parameters for attachment routes
export const AttachmentParamsSchema = z.object({
  emailId: uuidSchema,
  attachmentId: uuidSchema,
});

// Organization Header validation (using passthrough to ignore other headers Fastify might receive)
export const OrgHeaderSchema = z.object({
  'x-organization-id': uuidSchema,
}).passthrough();

// Fastify-compatible JSON schemas
export const fastifyEmailParamsSchema = zodToJsonSchema(EmailParamsSchema as any);
export const fastifyAttachmentParamsSchema = zodToJsonSchema(AttachmentParamsSchema as any);
export const fastifyOrgHeaderSchema = zodToJsonSchema(OrgHeaderSchema as any);
