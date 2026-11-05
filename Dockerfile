FROM node:24-alpine
RUN apk add --no-cache openssl
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY public ./public
COPY scripts ./scripts
COPY monitoring.json ./
RUN mkdir -p certs logs && chown node:node certs logs
USER node
ENV SERVER_ADDRESS=0.0.0.0
EXPOSE 8080 8443
CMD ["sh", "-c", "node scripts/generate-dev-cert.js && node src/server.js"]
