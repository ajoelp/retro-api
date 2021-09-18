FROM node:16-alpine as build
ARG NODE_ENV=production
WORKDIR /usr/src/app
COPY package.json yarn.lock ./
COPY prisma/ ./
RUN yarn install
COPY . ./
RUN yarn build

FROM node:16-alpine as build-runtime
ARG NODE_ENV=production
WORKDIR /usr/src/app
RUN apk update && apk add --no-cache \
  curl \
  bash \
  && rm -rf /var/cache/apk/*
RUN curl -sfL https://install.goreleaser.com/github.com/tj/node-prune.sh | bash -s -- -b /usr/local/bin
COPY package.json yarn.lock ./
COPY yarn.lock .
COPY prisma/ ./
RUN yarn install
COPY --from=build /usr/src/app/dist ./src
RUN /usr/local/bin/node-prune

FROM node:16-alpine
ENV NODE_ENV production
ENV APP_PORT 3333
EXPOSE 3333
WORKDIR /usr/src/app
RUN apk add --no-cache tini
COPY --chown=node:node --from=build-runtime /usr/src/app ./
USER node
ENTRYPOINT ["/sbin/tini", "--", "node"]
CMD ["./src/app/main.js"]
