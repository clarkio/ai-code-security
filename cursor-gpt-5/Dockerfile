FROM node:20-alpine

ENV NODE_ENV=production
WORKDIR /app

RUN addgroup -S app && adduser -S app -G app

COPY package*.json ./
RUN apk add --no-cache python3 make g++ \
  && npm install --omit=dev \
  && npm cache clean --force \
  && apk del python3 make g++

COPY src ./src
RUN mkdir -p data && chown -R app:app /app

USER app
EXPOSE 3000
CMD ["node", "src/server.js"]


