# SPDX-FileCopyrightText: 2026 Kevin
# SPDX-License-Identifier: AGPL-3.0-only

FROM node:24-alpine AS dependencies

WORKDIR /app

COPY backend/package.json backend/package-lock.json ./backend/
WORKDIR /app/backend
RUN npm ci --omit=dev

FROM dependencies AS verified-context

ARG IELTMPS_SOURCE_COMMIT
ARG IELTMPS_CONTEXT_MANIFEST_SHA256
ARG IELTMPS_CONTEXT_RECEIPT_SHA256

WORKDIR /verified-context

COPY .ieltmps-public-context.json ./.ieltmps-public-context.json
COPY developer/verify-public-container-context.mjs ./developer/verify-public-container-context.mjs
RUN node developer/verify-public-container-context.mjs \
      --receipt-only \
      --context /verified-context \
      --expected-commit "$IELTMPS_SOURCE_COMMIT" \
      --expected-manifest-sha256 "$IELTMPS_CONTEXT_MANIFEST_SHA256" \
      --expected-receipt-sha256 "$IELTMPS_CONTEXT_RECEIPT_SHA256"

COPY .dockerignore index.html ./
COPY assets ./assets
COPY css ./css
COPY js ./js
COPY src/styles ./src/styles
COPY templates ./templates
COPY backend/Dockerfile backend/package.json backend/package-lock.json backend/.env.example ./backend/
COPY backend/src ./backend/src
COPY backend/scripts ./backend/scripts
COPY backend/migrations ./backend/migrations
COPY backend/admin ./backend/admin
COPY backend/auth ./backend/auth
RUN node developer/verify-public-container-context.mjs \
      --full \
      --context /verified-context \
      --expected-commit "$IELTMPS_SOURCE_COMMIT" \
      --expected-manifest-sha256 "$IELTMPS_CONTEXT_MANIFEST_SHA256" \
      --expected-receipt-sha256 "$IELTMPS_CONTEXT_RECEIPT_SHA256"

FROM node:24-alpine AS runtime

WORKDIR /app

COPY --from=verified-context /verified-context/assets ./assets
COPY --from=verified-context /verified-context/css ./css
COPY --from=verified-context /verified-context/js ./js
COPY --from=verified-context /verified-context/src/styles ./src/styles
COPY --from=verified-context /verified-context/templates ./templates
COPY --from=verified-context /verified-context/index.html ./index.html
COPY --from=verified-context /verified-context/backend/package.json ./backend/package.json
COPY --from=verified-context /verified-context/backend/package-lock.json ./backend/package-lock.json
COPY --from=verified-context /app/backend/node_modules ./backend/node_modules
COPY --from=verified-context /verified-context/backend/src ./backend/src
COPY --from=verified-context /verified-context/backend/scripts ./backend/scripts
COPY --from=verified-context /verified-context/backend/migrations ./backend/migrations
COPY --from=verified-context /verified-context/backend/admin ./backend/admin
COPY --from=verified-context /verified-context/backend/auth ./backend/auth
RUN chmod -R a+rX /app/backend/auth

WORKDIR /app/backend
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000

EXPOSE 3000

USER node

CMD ["sh", "-c", "node scripts/migrate.mjs && node scripts/bootstrap-admin.mjs && node src/server.js"]
