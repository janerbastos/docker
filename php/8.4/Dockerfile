FROM php:8.4-fpm-alpine3.20

# Instalação de dependencias
RUN apk add --no-cache \
    msmtp \
    perl \
    wget \
    procps \
    shadow \
    libzip \
    libpng \
    libjpeg-turbo \
    libwebp \
    freetype \
    icu \
    icu-data-full \
    php82-pgsql \
    nginx \
    supervisor

RUN apk add --no-cache --virtual \
    build-essentials \
    icu-dev \
    icu-libs \
    zlib-dev \
    g++ \
    make \
    automake \
    autoconf \
    libzip-dev  \
    libpng-dev \
    libwebp-dev \
    libjpeg-turbo-dev \
    freetype-dev \
    libpq-dev && \
    docker-php-ext-configure gd --enable-gd --with-freetype --with-jpeg --with-webp && \
    docker-php-ext-install \
        gd \
        mysqli \
        pdo \
        pdo_mysql \
        pgsql \
        pdo_pgsql \
        intl \
        opcache \
        exif \
        zip && \
        apk del build-essentials && rm -rf /usr/src/php*

# Instalação do composer

RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" && \
    php -r "if (hash_file('sha384', 'composer-setup.php') === 'dac665fdc30fdd8ec78b38b9800061b4150413ff2e3b6f88543c636f7cd84f6db9189d43a81e5503cda447da73c7e5b6') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;" && \
    php composer-setup.php && \
    php -r "unlink('composer-setup.php');" && \
    mv composer.phar /usr/local/bin/composer
