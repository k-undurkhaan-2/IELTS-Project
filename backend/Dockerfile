# SPDX-FileCopyrightText: 2026 Kevin
# SPDX-License-Identifier: AGPL-3.0-only

# SECURITY GATE: node:24-alpine remains mutable. An independently approved
# registry digest is required before any authoritative production image build.
FROM node:24-alpine

WORKDIR /app

COPY backend/package*.json ./backend/
WORKDIR /app/backend
RUN npm ci --omit=dev

WORKDIR /app
COPY assets ./assets
COPY css ./css
COPY js ./js
COPY src/styles ./src/styles
COPY templates ./templates
COPY index.html ./index.html
COPY backend ./backend
COPY .ieltmps-build/public-listening-frontend/active.json /app/public/listening-frontend/active.json
COPY .ieltmps-build/public-listening-frontend/lpf-v1-1a576be93d7d-a2-fad166773fa6259a/manifest.json /app/public/listening-frontend/lpf-v1-1a576be93d7d-a2-fad166773fa6259a/manifest.json
COPY .ieltmps-build/public-listening-frontend/lpf-v1-1a576be93d7d-a2-fad166773fa6259a/payload/ /app/public/listening-frontend/lpf-v1-1a576be93d7d-a2-fad166773fa6259a/payload/
RUN chmod -R a+rX /app/backend/auth

WORKDIR /app/backend
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000

EXPOSE 3000

USER node

CMD ["sh", "-c", "node scripts/migrate.mjs && node scripts/bootstrap-admin.mjs && node src/server.js"]
