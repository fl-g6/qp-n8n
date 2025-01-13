ARG NODE_VERSION=20

# 1. Create an image to build n8n
FROM n8nio/base:${NODE_VERSION} AS builder

# COPY --chown=node:node turbo.json package.json .npmrc pnpm-lock.yaml pnpm-workspace.yaml jest.config.js tsconfig*.json ./
# COPY --chown=node:node scripts ./scripts
# COPY --chown=node:node packages ./packages
# COPY --chown=node:node patches ./patches

# RUN apk add --update jq
# RUN corepack enable && corepack prepare --activate
# USER node

# COPY ./packages/design-system/src/css/_tokens.quickplay.scss _tokens.scss

# Build the application from source
WORKDIR /src
COPY . /src
COPY ./packages/design-system/src/css/_tokens.quickplay.scss _tokens.scss
RUN --mount=type=cache,id=pnpm-store,target=/root/.local/share/pnpm/store --mount=type=cache,id=pnpm-metadata,target=/root/.cache/pnpm/metadata DOCKER_BUILD=true pnpm install --frozen-lockfile
# RUN NODE_ENV=production pnpm install --prod --no-optional

RUN pnpm build
#RUN rm -rf node_modules
RUN jq 'del(.pnpm.patchedDependencies)' package.json > package.json.tmp; mv package.json.tmp package.json
#RUN node scripts/trim-fe-packageJson.js
RUN node .github/scripts/trim-fe-packageJson.js

# Delete any source code, source-mapping, or typings
RUN find . -type f -name "*.ts" -o -name "*.js.map" -o -name "*.vue" -o -name "tsconfig.json" -o -name "*.tsbuildinfo" | xargs rm -rf

# USER root
# RUN rm -rf packages/@n8n_io/eslint-config packages/editor-ui/src packages/editor-ui/node_modules packages/design-system
# RUN rm -rf patches .npmrc *.yaml node_modules/.cache packages/**/node_modules/.cache packages/**/.turbo .config .cache .local .node /tmp/*

# Deploy the `n8n` package into /compiled
RUN mkdir /compiled
RUN NODE_ENV=production DOCKER_BUILD=true pnpm --filter=n8n --prod --no-optional deploy /compiled

# 2. Start with a new clean image with just the code that is needed to run n8n
FROM n8nio/base:${NODE_VERSION}
ARG N8N_RELEASE_TYPE=dev

WORKDIR /home/node
COPY --from=builder /compiled /usr/local/lib/node_modules/n8n
COPY docker/images/n8n/docker-entrypoint.sh /

RUN \
	cd /usr/local/lib/node_modules/n8n && \
	npm rebuild sqlite3 && \
	cd - && \
	ln -s /usr/local/lib/node_modules/n8n/bin/n8n /usr/local/bin/n8n && \
	mkdir .n8n && \
	chown node:node .n8n

ENV SHELL /bin/sh

USER node
ENV NODE_ENV=production
ENV N8N_RELEASE_TYPE=${N8N_RELEASE_TYPE}
ENTRYPOINT ["tini", "--", "/docker-entrypoint.sh"]
