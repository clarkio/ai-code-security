# Build stage
FROM node:18-alpine AS builder

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./


# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Remove development dependencies
RUN npm prune --production

# Production stage
FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install curl for health checks
RUN apk --no-cache add curl

# Copy built application from builder stage
COPY --from=builder /usr/src/app .

# Set environment variables
ENV NODE_ENV=production

# Expose the port the app runs on
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/api/v1/health || exit 1

# Run the application
CMD ["node", "src/server.js"]
