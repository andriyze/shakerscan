# ShakerScan UI
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS builder

WORKDIR /app

# The immutable Node image can lag Alpine's security repository by a few days.
# Pin the small security delta so a candidate cannot silently resolve different
# package revisions, and retry only this network-bound repository operation.
ARG APK_TOOLS_VERSION=3.0.7-r0
ARG OPENSSL_VERSION=3.5.8-r0
RUN set -eu; \
    attempt=1; \
    until apk add --no-cache --upgrade \
      "apk-tools=${APK_TOOLS_VERSION}" \
      "libapk=${APK_TOOLS_VERSION}" \
      "libcrypto3=${OPENSSL_VERSION}" \
      "libssl3=${OPENSSL_VERSION}"; do \
      if [ "$attempt" -ge 4 ]; then \
        echo "Pinned Alpine security update failed after 4 attempts" >&2; \
        exit 1; \
      fi; \
      sleep $((attempt * 3)); \
      attempt=$((attempt + 1)); \
    done

# Install pinned dependencies from the lockfile
COPY package.json package-lock.json ./
RUN npm ci

# Copy source
COPY . .

# Build-time app version (exposed to client)
ARG NEXT_PUBLIC_APP_VERSION=dev
ARG NEXT_PUBLIC_EXPECTED_API_BUILD_FINGERPRINT=unknown
ARG UI_SOURCE_REVISION=unknown
ENV NEXT_PUBLIC_APP_VERSION=$NEXT_PUBLIC_APP_VERSION
ENV NEXT_PUBLIC_EXPECTED_API_BUILD_FINGERPRINT=$NEXT_PUBLIC_EXPECTED_API_BUILD_FINGERPRINT
RUN printf '%s\n' "$NEXT_PUBLIC_APP_VERSION" > /app/UI_BUILD_VERSION
RUN printf '%s\n' "$NEXT_PUBLIC_EXPECTED_API_BUILD_FINGERPRINT" > /app/UI_EXPECTED_API_BUILD_FINGERPRINT
RUN printf '%s\n' "$UI_SOURCE_REVISION" > /app/UI_SOURCE_REVISION

# Build
RUN npm run build

# Production image
FROM node:24-alpine@sha256:e67514e5d0f6c46656005e1b693b2ec9d52e80b641307de684d4a015ba7a4eaf AS runner

WORKDIR /app

ENV NODE_ENV=production

ARG APK_TOOLS_VERSION=3.0.7-r0
ARG OPENSSL_VERSION=3.5.8-r0
RUN set -eu; \
    attempt=1; \
    until apk add --no-cache --upgrade \
      "apk-tools=${APK_TOOLS_VERSION}" \
      "libapk=${APK_TOOLS_VERSION}" \
      "libcrypto3=${OPENSSL_VERSION}" \
      "libssl3=${OPENSSL_VERSION}"; do \
      if [ "$attempt" -ge 4 ]; then \
        echo "Pinned Alpine security update failed after 4 attempts" >&2; \
        exit 1; \
      fi; \
      sleep $((attempt * 3)); \
      attempt=$((attempt + 1)); \
    done; \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

# Copy built assets
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
COPY --from=builder /app/UI_BUILD_VERSION ./UI_BUILD_VERSION
COPY --from=builder /app/UI_EXPECTED_API_BUILD_FINGERPRINT ./UI_EXPECTED_API_BUILD_FINGERPRINT
COPY --from=builder /app/UI_SOURCE_REVISION ./UI_SOURCE_REVISION

EXPOSE 3000

CMD ["node", "server.js"]
