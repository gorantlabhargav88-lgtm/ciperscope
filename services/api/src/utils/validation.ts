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

// Case Management
export const CreateCaseBodySchema = z.object({
  title: z.string().max(255),
  description: z.string().max(4000).optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
}).strict(); // Using .strict() equivalent to additionalProperties: false

export const fastifyCreateCaseBodySchema = zodToJsonSchema(CreateCaseBodySchema as any);

export const CaseParamsSchema = z.object({
  caseId: uuidSchema,
});

export const CaseListQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  cursor: z.string().optional(),
  status: z.enum(['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED']).optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
}).strict();

export const fastifyCaseParamsSchema = zodToJsonSchema(CaseParamsSchema as any);
export const fastifyCaseListQuerySchema = zodToJsonSchema(CaseListQuerySchema as any);

export const UpdateCaseBodySchema = z.object({
  title: z.string().max(255).optional(),
  description: z.string().max(4000).optional(),
  priority: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  status: z.enum(['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED']).optional(),
}).strict();

export const fastifyUpdateCaseBodySchema = zodToJsonSchema(UpdateCaseBodySchema as any);

export const AssignCaseBodySchema = z.object({
  assignedUserId: uuidSchema.nullable(),
}).strict();

export const fastifyAssignCaseBodySchema = zodToJsonSchema(AssignCaseBodySchema as any);

export const LinkCaseEmailBodySchema = z.object({
  emailId: uuidSchema,
}).strict();

export const fastifyLinkCaseEmailBodySchema = zodToJsonSchema(LinkCaseEmailBodySchema as any);

export const CreateCaseNoteBodySchema = z.object({
  content: z.string().min(1).max(4000),
}).strict();

export const fastifyCreateCaseNoteBodySchema = zodToJsonSchema(CreateCaseNoteBodySchema as any);
