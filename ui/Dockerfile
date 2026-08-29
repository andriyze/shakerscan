# ShakerScan UI
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS builder

WORKDIR /app

# Apply current Alpine security updates even when the immutable Node manifest
# predates a repository package fix by a few days.
RUN apk upgrade --no-cache

# Install pinned dependencies from the lockfile
COPY package.json package-lock.json ./
RUN npm ci

# Copy source
COPY . .

# Build-time app version (exposed to client)
ARG NEXT_PUBLIC_APP_VERSION=dev
ARG UI_SOURCE_REVISION=unknown
ENV NEXT_PUBLIC_APP_VERSION=$NEXT_PUBLIC_APP_VERSION
RUN printf '%s\n' "$NEXT_PUBLIC_APP_VERSION" > /app/UI_BUILD_VERSION
RUN printf '%s\n' "$UI_SOURCE_REVISION" > /app/UI_SOURCE_REVISION

# Build
RUN npm run build

# Production image
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS runner

WORKDIR /app

ENV NODE_ENV=production

RUN apk upgrade --no-cache && \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

# Copy built assets
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
COPY --from=builder /app/UI_BUILD_VERSION ./UI_BUILD_VERSION
COPY --from=builder /app/UI_SOURCE_REVISION ./UI_SOURCE_REVISION

EXPOSE 3000

CMD ["node", "server.js"]
