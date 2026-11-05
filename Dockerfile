FROM node:22-alpine

# Install build dependencies for better-sqlite3 native addon
RUN apk add --no-cache python3 make g++ sqlite

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Create default directories for SQLite, single host_volumes mount, and runtimes with full write permissions
RUN mkdir -p /data/db /var/webdav /tmp/vaultdav-syncthing-runtime \
    && chmod -R 777 /data /var/webdav /tmp/vaultdav-syncthing-runtime /app

# Expose Web App and WebDAV (/dav) on port 3000
EXPOSE 3000

CMD ["npm", "run", "start"]
