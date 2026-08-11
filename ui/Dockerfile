# ShakerScan UI
FROM node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS builder

WORKDIR /app

# Install pinned dependencies from the lockfile
COPY package.json package-lock.json ./
RUN npm ci

# Copy source
COPY . .

# Build-time app version (exposed to client)
ARG NEXT_PUBLIC_APP_VERSION=dev
ENV NEXT_PUBLIC_APP_VERSION=$NEXT_PUBLIC_APP_VERSION
RUN printf '%s\n' "$NEXT_PUBLIC_APP_VERSION" > /app/UI_BUILD_VERSION

# Build
RUN npm run build

# Production image
FROM node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS runner

WORKDIR /app

ENV NODE_ENV=production

# Copy built assets
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
COPY --from=builder /app/UI_BUILD_VERSION ./UI_BUILD_VERSION

EXPOSE 3000

CMD ["node", "server.js"]
