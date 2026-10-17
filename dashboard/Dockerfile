FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
EXPOSE 5173
# Listen on all interfaces INSIDE the container so Docker can forward to it;
# docker-compose.yml publishes it on 127.0.0.1 only.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
