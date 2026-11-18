FROM node:22-alpine

WORKDIR /app

COPY package.json glama.json server.json ./
COPY scripts/mcp-stdio.mjs ./scripts/mcp-stdio.mjs
COPY packages/clearinghouse-worker/mcp-tools.json ./packages/clearinghouse-worker/mcp-tools.json

ENV NODE_ENV=production

CMD ["node", "scripts/mcp-stdio.mjs"]
