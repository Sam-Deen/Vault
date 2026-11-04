FROM node:24-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY public ./public
RUN mkdir -p data && chown node:node data
USER node
ENV SERVER_ADDRESS=0.0.0.0
EXPOSE 8080 8443
CMD ["node", "src/server.js"]
