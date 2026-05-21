FROM node:20-alpine AS base

RUN addgroup -S app && adduser -S app -G app

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm cache clean --force

COPY . .

RUN mkdir -p /app/data && chown -R app:app /app

USER app

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000
ENV DATABASE_PATH=/app/data/notes.db

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:3000/login || exit 1

CMD ["sh", "-c", "node src/db/init.js && node src/server.js"]
