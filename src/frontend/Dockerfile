# build stage
FROM node:lts-alpine AS builder

WORKDIR /app

COPY package*.json ./

RUN npm install
# RUN npm install -g npm-check-updates && \
#     ncu -u && \
#     npm install

COPY . .

RUN npm run build

# prod stage

FROM node:lts-alpine

RUN apk update
# RUN apk update && \
#     apk add --no-cache nginx

WORKDIR /app

ENV NODE_ENV=production

# COPY default.conf /etc/nginx/http.d/default.conf
# COPY ./run.sh ./run.sh
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# CMD ["sh", "run.sh"]
CMD ["node", "server.js"]
