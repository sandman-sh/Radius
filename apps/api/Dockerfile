FROM node:20-alpine AS runner

WORKDIR /app

# Install curl for container healthchecks
RUN apk add --no-cache curl

# Copy root workspace manifests
COPY package.json package-lock.json ./
COPY apps/api/package.json ./apps/api/

# Install dependencies (production workspaces)
RUN npm ci --omit=dev --workspace=@radius/api

# Copy API source code
COPY apps/api/src ./apps/api/src
COPY apps/api/package.json ./apps/api/

ENV NODE_ENV=production
ENV PORT=4100
EXPOSE 4100

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:4100/api/health || exit 1

CMD ["node", "apps/api/src/server.js"]
