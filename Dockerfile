FROM node:18-alpine

WORKDIR /usr/src/app

ENV NODE_ENV=production

COPY package*.json ./

RUN npm install --production

COPY . .

RUN npm run build

EXPOSE 3000

CMD [ "npm", "run", "build:start" ]
