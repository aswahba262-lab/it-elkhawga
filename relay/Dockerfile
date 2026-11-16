# IT ELKHAWGA Relay - production-ish image for free/paid hosts (Render, Fly, Koyeb, VPS)
FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package.json ./
COPY server.js ./

# SQLite lives here; mount a persistent volume at /data on hosts that support it.
ENV DATA_DIR=/data
RUN mkdir -p /data

EXPOSE 8787
CMD ["node", "server.js"]
