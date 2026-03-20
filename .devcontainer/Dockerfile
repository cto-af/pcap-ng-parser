FROM mcr.microsoft.com/devcontainers/javascript-node

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
   && apt-get -y upgrade

RUN npm install -g playwright npm-check-updates

USER node
RUN npx playwright install --with-deps
