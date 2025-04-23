# Etapa de build
FROM debian:bullseye-slim AS builder

ARG NGINX_VERSION=1.25.5
ARG MODSECURITY_VERSION=3.0.13
ARG MODSECURITY_NGINX_VERSION=1.0.3

RUN apt-get update && apt-get install -y \
    build-essential ca-certificates curl git g++ \
    libpcre3 libpcre3-dev libssl-dev libxml2 libxml2-dev \
    libyajl-dev pkgconf libtool automake autoconf zlib1g-dev \
    wget libcurl4-openssl-dev libgeoip-dev liblmdb-dev \
    liblua5.3-dev libmaxminddb-dev doxygen cmake

# Build ModSecurity
WORKDIR /opt
RUN git clone --depth 1 -b v${MODSECURITY_VERSION} https://github.com/SpiderLabs/ModSecurity && \
    cd ModSecurity && git submodule update --init --depth 1 && \
    ./build.sh && ./configure && make -j$(nproc) && make install

# Build conector nginx
RUN git clone --depth 1 -b v${MODSECURITY_NGINX_VERSION} https://github.com/SpiderLabs/ModSecurity-nginx.git

# Build NGINX
RUN curl -LO http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -xzvf nginx-${NGINX_VERSION}.tar.gz && \
    cd nginx-${NGINX_VERSION} && \
    ./configure --prefix=/opt/nginx --with-compat --add-dynamic-module=../ModSecurity-nginx && \
    make -j$(nproc) && make install

# Etapa final
FROM debian:bullseye-slim AS nginx

# Copia binários e bibliotecas necessárias
COPY --from=builder /opt/nginx /opt/nginx
COPY --from=builder /usr/local/modsecurity /usr/local/modsecurity
COPY --from=builder /opt/nginx/modules/ngx_http_modsecurity_module.so /etc/nginx/modules/

# Instala dependências de runtime
RUN apt-get update && apt-get install -y \
    libxml2 libyajl2 liblua5.3 libmaxminddb0 libcurl4 libgeoip1 \
    zlib1g libssl1.1 && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/nginx/sbin:$PATH"
ENV LD_LIBRARY_PATH=/usr/local/modsecurity/lib

# Copia arquivos de configuração e regras
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsec /etc/nginx/modsec/
COPY mime.types /etc/nginx/mime.types

CMD ["nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"]
