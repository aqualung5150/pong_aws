####################
#	build stage
####################

FROM node:lts-alpine AS builder

WORKDIR /app

COPY package*.json ./

RUN npm install
# RUN npm install -g npm-check-updates && \
#     ncu -u && \
#     npm install

COPY . .
COPY *.png /photo/

## prisma
RUN npx prisma generate

RUN npm run build

####################
# production stage
####################

FROM node:lts-alpine

WORKDIR /app

ARG NODE_ENV=production

ENV NODE_ENV=${NODE_ENV}

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json .
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/*.png /photo/

RUN npm install --only-production
# RUN npm install -g npm-check-updates && \
#     ncu -u && \
#     npm install --only-production

# prisma
COPY ./prisma ./prisma
EXPOSE 3001

CMD ["npm", "run", "start:migrate:prod"]

#----------------------------------------#