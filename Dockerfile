FROM node:22-alpine

# Install build dependencies for better-sqlite3 native addon
RUN apk add --no-cache python3 make g++ sqlite

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Create default directories for SQLite and single host_volumes mount
RUN mkdir -p /data/db /var/webdav

EXPOSE 3000

CMD ["npm", "run", "start"]
