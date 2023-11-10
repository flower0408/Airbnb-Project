FROM nginx:latest

COPY ./api_gateway.conf /etc/nginx/conf.d/api_gateway.conf
COPY ./cert  /etc/nginx/cert
RUN rm /etc/nginx/conf.d/default.conf