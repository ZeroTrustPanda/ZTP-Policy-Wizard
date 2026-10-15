FROM node:20-alpine

WORKDIR /app

# Trust a local TLS-inspecting proxy CA (e.g. Zscaler) if one is dropped in ./certs
# (gitignored — not meant to be portable/committed). Harmless no-op otherwise.
COPY certs/ /usr/local/share/ca-certificates/extra/
RUN cat /usr/local/share/ca-certificates/extra/*.crt >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null; \
    true
ENV NODE_OPTIONS=--use-openssl-ca

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server ./server
COPY public ./public

RUN mkdir -p /app/logs

ENV ZTP_PORT=3000
ENV ZTP_HOST=0.0.0.0

EXPOSE 3000

CMD ["node", "server/index.js"]
