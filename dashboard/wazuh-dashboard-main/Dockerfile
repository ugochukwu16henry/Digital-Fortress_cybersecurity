ARG NODE_VERSION=20.18.3
FROM node:${NODE_VERSION} AS base

ENV HOME '.'
RUN apt-get update && \
  apt-get -y install xvfb gconf-service libasound2 libatk1.0-0 libc6 libcairo2 libcups2 \
  libdbus-1-3 libexpat1 libfontconfig1 libgcc1 libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 \
  libgtk-3-0 libnspr4 libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 \
  libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 \
  libxtst6 ca-certificates fonts-liberation libappindicator1 libnss3 lsb-release xdg-utils wget gnupg default-jre-headless && \
  rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-linux.gpg \
  && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-linux.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
  && apt-get update \
  && apt-get install -y rsync jq libarchive-tools google-chrome-stable awscli --no-install-recommends \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN groupadd -r opensearch-dashboards && useradd -r -g opensearch-dashboards opensearch-dashboards && mkdir /home/opensearch-dashboards && chown opensearch-dashboards:opensearch-dashboards /home/opensearch-dashboards

ENV OPENSEARCH_DASHBOARDS_PORT=8080
EXPOSE 8080
USER opensearch-dashboards
