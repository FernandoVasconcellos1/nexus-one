FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY . .
RUN ls -la
EXPOSE 3000
CMD ["node", "servidor.js"]
