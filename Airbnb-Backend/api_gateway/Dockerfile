FROM nginx:latest

COPY ./api_gateway.conf /etc/nginx/conf.d/api_gateway.conf
COPY ./cert  /etc/nginx/cert
RUN rm /etc/nginx/conf.d/default.conf

COPY ./opentelemetry-webserver-sdk-x64-linux/opentelemetry-webserver-sdk-x64-linux/opentelemetry-webserver-sdk/ /opt/opentelemetry-webserver-sdk/

RUN cd /opt/opentelemetry-webserver-sdk; ./install.sh
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/opentelemetry-webserver-sdk/sdk_lib/lib

RUN echo "load_module /opt/opentelemetry-webserver-sdk/WebServerModule/Nginx/1.25.3/ngx_http_opentelemetry_module.so;\n$(cat /etc/nginx/nginx.conf)" > /etc/nginx/nginx.conf

COPY opentelemetry_module.conf /etc/nginx/conf.d
