# Use modern Node.js 22 (includes native node:sqlite)
FROM node:22-alpine

WORKDIR /app

# Copy application files
COPY . .

# Expose web port
EXPOSE 3000

ENV PORT=3000
ENV NODE_ENV=production

# Start StockSense
CMD ["node", "server.js"]
