# Multi-stage build for Node.js API service
FROM node:20-alpine AS builder

WORKDIR /build

# Install pnpm
RUN npm install -g pnpm@10.28.0

# Copy workspace configuration
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json ./

# Copy all workspace packages
COPY packages ./packages
COPY services/api ./services/api

# Install dependencies
RUN pnpm install --frozen-lockfile

# Generate Prisma client
RUN pnpm -C packages/database db:generate

# Build the API and every workspace package it actually depends on (its full
# dependency closure, in topological order) — NOT just packages/database.
# Every @ciperscope/* package resolves "main"/"types" to dist/index.js, so
# any dependency skipped here would fail to `require()` at container
# runtime with no build-time signal.
RUN pnpm --filter @ciperscope/api... build

# Final runtime stage
FROM node:20-alpine

WORKDIR /app

# Install pnpm for runtime
RUN npm install -g pnpm@10.28.0

# node:20-alpine's OpenSSL 3.x isn't detectable by Prisma's own runtime
# probe without this package present (it otherwise silently defaults to
# assuming OpenSSL 1.1.x and loads the wrong query-engine binary even
# though the correct linux-musl-openssl-3.0.x one was generated — see the
# binaryTargets comment in packages/database/prisma/schema.prisma).
RUN apk add --no-cache openssl

# node:20-alpine already ships a non-root "node" user (uid/gid 1000) — reuse
# it instead of creating a new one (addgroup -g 1000 fails: that gid is
# already taken by the image's own "node" group).

# Preserve the workspace layout (root package.json + pnpm-workspace.yaml +
# packages/* + services/api/*) instead of flattening services/api's files
# into /app — a flattened layout means the LAST `COPY .../package.json ./`
# below would silently overwrite the API's own package.json (with fastify
# etc. as dependencies) with the monorepo root's package.json (which has
# none), so `pnpm install --prod` would install almost nothing and the
# image would fail at startup with MODULE_NOT_FOUND.
COPY --from=builder /build/pnpm-workspace.yaml ./
COPY --from=builder /build/pnpm-lock.yaml ./
COPY --from=builder /build/package.json ./
COPY --from=builder /build/packages ./packages
COPY --from=builder /build/services/api/dist ./services/api/dist
COPY --from=builder /build/services/api/package.json ./services/api/package.json

# The packages/* directories copied above carry each package's node_modules
# from the builder stage, including symlinks with relative targets like
# ../../../node_modules/.pnpm/... — paths that don't exist yet in THIS
# (fresh) image until the install below populates them. A stale, dangling
# node_modules tree sitting there confuses pnpm's install into leaving
# services/api/node_modules empty entirely. Strip them first so every
# package starts from a clean, unambiguous state.
RUN find ./packages -mindepth 2 -maxdepth 2 -type d -name node_modules -prune -exec rm -rf {} +

# Install prod-only dependencies directly (not a full install followed by
# `pnpm prune --prod`) — `pnpm prune` run unfiltered at this workspace root
# does not correctly preserve per-member symlinks (empirically verified: it
# silently removes services/api/node_modules/fastify even though fastify is
# a real, non-dev dependency), leaving the image unable to `require()` it.
# A `--filter`-scoped install has the same problem for a different reason
# (it fails to symlink into services/api/node_modules at all when most
# other pnpm-workspace.yaml members — apps/*, the other services/* — aren't
# present on disk). An unfiltered, prod-only install has neither issue.
RUN pnpm install --frozen-lockfile --prod

# `prisma`, the CLI needed to generate the client, is a devDependency (never
# installed above) — the builder stage's generated client also lives inside
# the builder's own node_modules and is never copied here. Fetch the exact
# pinned Prisma CLI version via npx (standalone, outside the workspace
# dependency tree) to generate the client fresh in THIS image instead. The
# version MUST match packages/database/package.json's "prisma" devDependency
# (lockfile-resolved to 5.22.0) — a mismatched CLI/@prisma/client version
# pair fails at runtime, not at generate time.
RUN npx --yes prisma@5.22.0 generate --schema=packages/database/prisma/schema.prisma

# /app/data/emails is where docker-compose mounts the shared
# raw_email_storage volume (RAW_EMAIL_STORAGE_PATH). A named volume used for
# the first time is seeded from whatever already exists at that path in the
# image — pre-creating it here, owned by node, is what lets the non-root
# "node" user write into it; otherwise Docker creates the mount point owned
# by root and every ingest fails with EACCES.
RUN mkdir -p /app/data/emails

# Set ownership
RUN chown -R node:node /app

USER node

EXPOSE 3000

# The callback-only form never calls process.exit() and the response's
# keep-alive socket stays in Node's http.Agent pool, so the event loop
# never empties and the script never exits on its own — every healthcheck
# run hit the 10s timeout regardless of the actual HTTP result. `agent:
# false` closes the socket immediately after the response, and the
# explicit process.exit() makes success/failure immediate either way.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node -e "require('http').get({host:'localhost',port:3000,path:'/health',agent:false}, (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "services/api/dist/index.js"]
