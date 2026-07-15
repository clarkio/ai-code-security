FROM node:24-bookworm-slim AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM dependencies AS build
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY scripts ./scripts
RUN npm run build

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts=false \
    && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY src/views ./src/views
COPY public ./public
COPY migrations ./migrations
USER node
EXPOSE 3000
CMD ["node", "dist/src/server.js"]
