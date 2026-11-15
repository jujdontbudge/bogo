# The agent's image: Claude Code, BOGO's stdio shim and the bypass suite.
# It holds no BOGO secret; its only BOGO credential is the agent token,
# given at run time from sandbox/.env.
FROM node:26.12.1-bookworm-slim
# ca-certificates for TLS to the model host; nftables only so the bypass suite
# can show `nft flush ruleset` failing without NET_ADMIN.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates nftables \
 && rm -rf /var/lib/apt/lists/*
ARG CLAUDE_CODE_VERSION=2.1.325
RUN npm install -g --omit=dev "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && npm cache clean --force
COPY bin/bogo-shim bin/bogo-bypass /usr/local/bin/
COPY mcp.json /etc/bogo/mcp.json
USER node
WORKDIR /work
ENV HOME=/work
