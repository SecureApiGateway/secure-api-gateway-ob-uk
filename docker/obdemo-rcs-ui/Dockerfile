### STAGE 1: Build ###
FROM node:9.11.1 as build
RUN mkdir /usr/src/app
WORKDIR /usr/src/app
ENV PATH /usr/src/app/node_modules/.bin:$PATH
COPY package.json /usr/src/app/package.json
RUN npm install --silent
RUN npm install react-scripts -g --silent
COPY . /usr/src/app
RUN npm run build

### STAGE 2: Production Environment ###
FROM nginx:1.13.12-alpine
RUN mkdir /usr/share/nginx/html/rcs
COPY --from=build /usr/src/app/build /usr/share/nginx/html/rcs
EXPOSE 80
# ENV REACT_APP_API_URL /rcs-api
# CMD ["nginx", "-g", "daemon off;"]

COPY docker-entrypoint.sh ./
CMD "./docker-entrypoint.sh"
