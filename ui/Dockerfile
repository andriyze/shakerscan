# DAST Scanner UI
FROM node:20-alpine AS builder

WORKDIR /app

# Install pinned dependencies from the lockfile
COPY package.json package-lock.json ./
RUN npm ci

# Copy source
COPY . .

# Build-time app version (exposed to client)
ARG NEXT_PUBLIC_APP_VERSION=dev
ENV NEXT_PUBLIC_APP_VERSION=$NEXT_PUBLIC_APP_VERSION

# Build
RUN npm run build

# Production image
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Copy built assets
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

EXPOSE 3000

CMD ["node", "server.js"]
