FROM node:18-alpine

WORKDIR /usr/src/app

COPY package.json package-lock.json ./

RUN npm install

COPY . .

ENV NODE_ENV=production

RUN npm run build

EXPOSE 5000

CMD [ "npm", "run", "build:start" ]
