# Minimal, secure Dockerfile
FROM node:18-alpine AS base
WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci --production

COPY . .

# Create non-root user
RUN addgroup -S app && adduser -S -G app app
RUN chown -R app:app /app
USER app

EXPOSE 3000
CMD ["node", "src/index.js"]
