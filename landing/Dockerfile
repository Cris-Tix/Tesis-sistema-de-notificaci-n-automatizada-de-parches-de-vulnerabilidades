# Lightweight static server for the single-file product landing.
FROM nginx:alpine

COPY index.html /usr/share/nginx/html/index.html
COPY env.js     /usr/share/nginx/html/env.js
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Runtime env injection: writes env.js from DASHBOARD_URL/LANDING_URL before nginx starts.
COPY 40-env.sh /docker-entrypoint.d/40-env.sh
RUN chmod +x /docker-entrypoint.d/40-env.sh

EXPOSE 80
