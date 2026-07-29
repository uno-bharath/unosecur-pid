FROM node:22-bookworm-slim AS workspace

ENV PNPM_HOME=/pnpm
ENV PATH=${PNPM_HOME}:${PATH}

RUN apt-get update \
  && apt-get install --yes --no-install-recommends ca-certificates curl openssl \
  && rm -rf /var/lib/apt/lists/* \
  && npm install --global pnpm@10.30.0

WORKDIR /workspace

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json eslint.config.mjs ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json

RUN pnpm install --frozen-lockfile

COPY . .

RUN pnpm --filter @unosecur/api prisma:generate

ARG NEXT_PUBLIC_API_URL=http://localhost:4000/api
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

RUN pnpm build

FROM workspace AS api

ENV NODE_ENV=production
EXPOSE 4000

CMD ["sh", "-c", "pnpm --filter @unosecur/api exec prisma migrate deploy && pnpm --filter @unosecur/api prisma:seed && pnpm --filter @unosecur/api start"]

FROM workspace AS web

ENV NODE_ENV=production
EXPOSE 3000

CMD ["pnpm", "--filter", "@unosecur/web", "start", "--hostname", "0.0.0.0", "--port", "3000"]
