FROM composer:1.9 as composer-build
    ARG MISP_TAG
    WORKDIR /tmp
    ADD https://raw.githubusercontent.com/MISP/MISP/${MISP_TAG}/app/composer.json /tmp
    RUN composer install --ignore-platform-reqs

FROM debian:buster-slim as php-build
    RUN apt-get update; apt-get install -y --no-install-recommends \
        gcc \
        make \
        libfuzzy-dev \
        ca-certificates \
        php \
        php-dev \
        php-pear \
        && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

        RUN cp /usr/lib/x86_64-linux-gnu/libfuzzy.* /usr/lib; pecl install ssdeep

FROM debian:buster-slim as python-build
    RUN apt-get update; apt-get install -y --no-install-recommends \
        gcc \
        git \
        python3 \
        python3-dev \
        python3-setuptools \
        python3-wheel \
        libfuzzy-dev \
        ca-certificates \
        && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

    RUN mkdir /wheels

    WORKDIR /tmp
    RUN git clone --depth 1 https://github.com/CybOXProject/mixbox.git; \
        cd mixbox || exit; python3 setup.py bdist_wheel -d /wheels

    # install python-maec
    RUN git clone --depth 1 https://github.com/MAECProject/python-maec.git; \
        cd python-maec || exit; python3 setup.py bdist_wheel -d /wheels

    # install python-cybox
    RUN git clone --depth 1 https://github.com/CybOXProject/python-cybox.git; \
        cd python-cybox || exit; python3 setup.py bdist_wheel -d /wheels

    # install python stix
    RUN git clone --depth 1 https://github.com/STIXProject/python-stix.git; \
        cd python-stix || exit; python3 setup.py bdist_wheel -d /wheels

    # install STIX2.0 library to support STIX 2.0 export:
    RUN git clone --depth 1 https://github.com/MISP/cti-python-stix2.git; \
        cd cti-python-stix2 || exit; python3 setup.py bdist_wheel -d /wheels

    # install PyMISP
    RUN git clone --depth 1 https://github.com/MISP/PyMISP.git; \
        cd PyMISP || exit; python3 setup.py bdist_wheel -d /wheels

    # install pydeep
    RUN git clone --depth 1 https://github.com/coolacid/pydeep.git; \
        cd pydeep || exit; python3 setup.py bdist_wheel -d /wheels

FROM debian:buster-slim
ENV DEBIAN_FRONTEND noninteractive
ARG MISP_TAG
ARG PHP_VER

# OS Packages
    RUN apt-get update; apt-get install -y --no-install-recommends \
        # Requirements:
        procps \
        sudo \
        nginx \
        supervisor \
        git \
        cron \
        openssl \
        gpg-agent gpg \
        ssdeep \
        libfuzzy2 \
        mariadb-client \
        rsync \
        # Python Requirements
        python3 \
        python3-setuptools \
        python3-pip \
        # PHP Requirements
        php \
        php-xml \
        php-mbstring \
        php-mysql \
        php-redis \
        php-gd \
        php-fpm \
        php-zip \
        # Unsure we need these
        zip unzip \
        && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# MISP code
    # Download MISP using git in the /var/www/ directory.
    RUN git clone --branch ${MISP_TAG} --depth 1 https://github.com/MISP/MISP.git /var/www/MISP; \
        # We build the MISP modules outside, so we don't need to grab those submodules
        cd /var/www/MISP/app || exit; git submodule update --init --recursive .;

# Python Modules
    COPY --from=python-build /wheels /wheels
    RUN pip3 install --no-cache-dir /wheels/*.whl plyara pyzmq redis python-magic lief && rm -rf /wheels

# PHP
    # Install ssdeep prebuild, latest composer, then install the app's PHP deps
    COPY --from=php-build /usr/lib/php/${PHP_VER}/ssdeep.so /usr/lib/php/${PHP_VER}/ssdeep.so
    COPY --from=composer-build /tmp/Vendor /var/www/MISP/app/Vendor
    COPY --from=composer-build /tmp/Plugin /var/www/MISP/app/Plugin
    RUN for dir in /etc/php/*; do echo "extension=ssdeep.so" > "$dir/mods-available/ssdeep.ini"; done \
        ;phpenmod redis \
    # Enable CakeResque with php-gnupgp
        ;phpenmod gnupg \
    # Enable ssdeep we build earlier
        ;phpenmod ssdeep \
    # To use the scheduler worker for scheduled tasks, do the following:
        ;cp -fa /var/www/MISP/INSTALL/setup/config.php /var/www/MISP/app/Plugin/CakeResque/Config/config.php

# nginx
    RUN rm /etc/nginx/sites-enabled/*; mkdir /run/php /etc/nginx/certs
    COPY files/etc/nginx/misp /etc/nginx/sites-available/misp
    COPY files/etc/nginx/misp-secure /etc/nginx/sites-available/misp-secure
    COPY files/etc/nginx/misp80 /etc/nginx/sites-available/misp80
    COPY files/etc/nginx/misp80-noredir /etc/nginx/sites-available/misp80-noredir

# Make a copy of the file store, so we can sync from it
    RUN cp -R /var/www/MISP/app/files /var/www/MISP/app/files.dist

# Make a copy of the configurations, so we can sync from it
    RUN cp -R /var/www/MISP/app/Config /var/www/MISP/app/Config.dist

# Entrypoints
    COPY files/etc/supervisor/supervisor.conf /etc/supervisor/conf.d/supervisord.conf
    COPY files/entrypoint_fpm.sh /
    COPY files/entrypoint_nginx.sh /
    COPY files/entrypoint_cron.sh /
    COPY files/entrypoint_workers.sh /
    COPY files/entrypoint.sh /
    ENTRYPOINT [ "/entrypoint.sh" ]

# Change Workdirectory
    WORKDIR /var/www/MISP
