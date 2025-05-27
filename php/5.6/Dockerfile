# Stage 1: Build stage
FROM php:5.6-fpm-alpine3.4 as builder

# Instala dependências de build
RUN apk add --no-cache --virtual .build-deps \
    zlib-dev \
    g++ \
    make \
    autoconf \
    libpng-dev \
    libjpeg-turbo-dev \
    freetype-dev

# Configura e instala extensões PHP necessárias
RUN docker-php-ext-configure gd --with-freetype-dir=/usr/include/ --with-jpeg-dir=/usr/include/ && \
    docker-php-ext-install gd mysqli pdo pdo_mysql zip

# Instala o Composer (versão compatível com Laravel 4.2)
RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" && \
    php composer-setup.php --version=1.10.17 && \
    php -r "unlink('composer-setup.php');" && \
    mv composer.phar /usr/local/bin/composer

# Copia os arquivos do projeto
COPY . /var/www/html
WORKDIR /var/www/html

# Instala as dependências do projeto
RUN composer install --no-dev --optimize-autoloader

# Stage 2: Runtime stage
FROM php:5.6-fpm-alpine3.4

# Copia artefatos do builder
COPY --from=builder /usr/local/etc/php/conf.d /usr/local/etc/php/conf.d
COPY --from=builder /usr/local/lib/php/extensions /usr/local/lib/php/extensions
COPY --from=builder /usr/local/bin/composer /usr/local/bin/composer

# Instala apenas as dependências de runtime
RUN apk add --no-cache \
    libpng \
    libjpeg-turbo \
    freetype \
    nginx \
    supervisor \
    shadow

# Configura usuário e permissões
RUN mkdir -p /var/www/html && \
    chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html/storage

# Copia a aplicação do builder
COPY --from=builder /var/www/html /var/www/html

# Copia configurações do Nginx e PHP-FPM
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expõe as portas necessárias
EXPOSE 80 443

# Comando de inicialização
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]