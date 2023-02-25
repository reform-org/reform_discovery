FROM node AS npm
ARG VITE_ALWAYS_ONLINE_PEER_URL
WORKDIR /app
COPY . .
RUN npm ci
RUN npm run db:init
EXPOSE 3000 7071
CMD ["npm", "start"]
