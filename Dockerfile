# @hasna/accounts — accounts-serve cloud API (PURE REMOTE, cloud Postgres).
# ARM64 / Bun. Multi-stage: build with dev deps, run a lean prod image.
#
# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------------
FROM --platform=linux/arm64 oven/bun:1.3-slim AS build
WORKDIR /app

# Install all deps (dev included) against the committed lockfile.
COPY package.json bun.lock* bun.lockb* ./
RUN bun install --frozen-lockfile

# Build the bundles (cli/mcp/index/storage/sdk/server + .d.ts).
COPY tsconfig.json ./
COPY src ./src
COPY migrations ./migrations
RUN bun run build

# ---- runtime stage ---------------------------------------------------------
FROM --platform=linux/arm64 oven/bun:1.3-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app

# Production dependencies only.
COPY package.json bun.lock* bun.lockb* ./
RUN bun install --frozen-lockfile --production

# App artifacts.
COPY --from=build /app/dist ./dist
COPY migrations ./migrations
COPY hasna.contract.json ./hasna.contract.json
COPY docker/rds-global-bundle.pem /app/rds-global-bundle.pem

# Cloud service defaults. The DSN + signing secret are injected at runtime
# (injected by the runtime environment). The database CA bundle lets TLS
# verify the shared RDS certificate chain.
ENV HASNA_ACCOUNTS_STORAGE_MODE=cloud \
    NODE_EXTRA_CA_CERTS=/app/rds-global-bundle.pem \
    PORT=8080

EXPOSE 8080

# Default command runs the HTTP API. The one-shot migration task overrides the
# command with ["bun","dist/server/migrate.js"] (see the hasna-app module).
CMD ["bun", "dist/server/index.js"]
