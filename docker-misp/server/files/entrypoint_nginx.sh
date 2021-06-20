#!/bin/bash

MISP_APP_CONFIG_PATH=/var/www/MISP/app/Config
[ -z "$MYSQL_HOST" ] && MYSQL_HOST=db
[ -z "$MYSQL_PORT" ] && MYSQL_PORT=3306
[ -z "$MYSQL_USER" ] && MYSQL_USER=misp
[ -z "$MYSQL_PASSWORD" ] && MYSQL_PASSWORD=example
[ -z "$MYSQL_DATABASE" ] && MYSQL_DATABASE=misp
[ -z "$REDIS_FQDN" ] && REDIS_FQDN=redis
[ -z "$MISP_MODULES_FQDN" ] && MISP_MODULES_FQDN="http://misp-modules"
[ -z "$MYSQLCMD" ] && MYSQLCMD="mysql -u $MYSQL_USER -p$MYSQL_PASSWORD -P $MYSQL_PORT -h $MYSQL_HOST -r -N  $MYSQL_DATABASE"

ENTRYPOINT_PID_FILE="/entrypoint_apache.install"
[ ! -f $ENTRYPOINT_PID_FILE ] && touch $ENTRYPOINT_PID_FILE

setup_cake_config(){
    sed -i "s/'host' => 'localhost'.*/'host' => '$REDIS_FQDN',          \/\/ Redis server hostname/" "/var/www/MISP/app/Plugin/CakeResque/Config/config.php"
}

init_misp_config(){
    [ -f $MISP_APP_CONFIG_PATH/bootstrap.php ] || cp $MISP_APP_CONFIG_PATH.dist/bootstrap.default.php $MISP_APP_CONFIG_PATH/bootstrap.php
    [ -f $MISP_APP_CONFIG_PATH/database.php ] || cp $MISP_APP_CONFIG_PATH.dist/database.default.php $MISP_APP_CONFIG_PATH/database.php
    [ -f $MISP_APP_CONFIG_PATH/core.php ] || cp $MISP_APP_CONFIG_PATH.dist/core.default.php $MISP_APP_CONFIG_PATH/core.php
    [ -f $MISP_APP_CONFIG_PATH/config.php ] || cp $MISP_APP_CONFIG_PATH.dist/config.default.php $MISP_APP_CONFIG_PATH/config.php
    [ -f $MISP_APP_CONFIG_PATH/email.php ] || cp $MISP_APP_CONFIG_PATH.dist/email.php $MISP_APP_CONFIG_PATH/email.php
    [ -f $MISP_APP_CONFIG_PATH/routes.php ] || cp $MISP_APP_CONFIG_PATH.dist/routes.php $MISP_APP_CONFIG_PATH/routes.php

    echo "Configure MISP | Set DB User, Password and Host in database.php"
    sed -i "s/localhost/$MYSQL_HOST/" $MISP_APP_CONFIG_PATH/database.php
    sed -i "s/db\s*login/$MYSQL_USER/" $MISP_APP_CONFIG_PATH/database.php
    sed -i "s/db\s*password/$MYSQL_PASSWORD/" $MISP_APP_CONFIG_PATH/database.php
    sed -i "s/'database' => 'misp'/'database' => '$MYSQL_DATABASE'/" $MISP_APP_CONFIG_PATH/database.php

    echo "Configure sane defaults"
    /var/www/MISP/app/Console/cake Admin setSetting "MISP.redis_host" "$REDIS_FQDN"
    /var/www/MISP/app/Console/cake Admin setSetting "MISP.baseurl" "$HOSTNAME"
    /var/www/MISP/app/Console/cake Admin setSetting "MISP.python_bin" $(which python3)

    /var/www/MISP/app/Console/cake Admin setSetting "Plugin.ZeroMQ_redis_host" "$REDIS_FQDN"
    /var/www/MISP/app/Console/cake Admin setSetting "Plugin.ZeroMQ_enable" true

    /var/www/MISP/app/Console/cake Admin setSetting "Plugin.Enrichment_services_enable" true
    /var/www/MISP/app/Console/cake Admin setSetting "Plugin.Enrichment_services_url" "$MISP_MODULES_FQDN"

    /var/www/MISP/app/Console/cake Admin setSetting "Plugin.Import_services_enable" true
    /var/www/MISP/app/Console/cake Admin setSetting "Plugin.Import_services_url" "$MISP_MODULES_FQDN"

    /var/www/MISP/app/Console/cake Admin setSetting "Plugin.Export_services_enable" true
    /var/www/MISP/app/Console/cake Admin setSetting "Plugin.Export_services_url" "$MISP_MODULES_FQDN"

    /var/www/MISP/app/Console/cake Admin setSetting "Plugin.Cortex_services_enable" false
}

init_misp_files(){
    if [ ! -f /var/www/MISP/app/files/INIT ]; then
        cp -R /var/www/MISP/app/files.dist/* /var/www/MISP/app/files
        touch /var/www/MISP/app/files/INIT
    fi
}

init_ssl() {
    if [[ (! -f /etc/nginx/certs/cert.pem) || (! -f /etc/nginx/certs/key.pem) ]];
    then
        cd /etc/nginx/certs
        openssl req -x509 -subj '/CN=localhost' -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
    fi
}

init_mysql(){
    # Test when MySQL is ready....
    # wait for Database come ready
    isDBup () {
        echo "SHOW STATUS" | $MYSQLCMD 1>/dev/null
        echo $?
    }

    isDBinitDone () {
        # Table attributes has existed since at least v2.1
        echo "DESCRIBE attributes" | $MYSQLCMD 1>/dev/null
        echo $?
    }

    RETRY=100
    until [ $(isDBup) -eq 0 ] || [ $RETRY -le 0 ] ; do
        echo "Waiting for database to come up"
        sleep 5
        RETRY=$(( RETRY - 1))
    done
    if [ $RETRY -le 0 ]; then
        >&2 echo "Error: Could not connect to Database on $MYSQL_HOST:$MYSQL_PORT"
        exit 1
    fi

    if [ $(isDBinitDone) -eq 0 ]; then
        echo "Database has already been initialized"
    else
        echo "Database has not been initialized, importing MySQL scheme..."
        $MYSQLCMD < /var/www/MISP/INSTALL/MYSQL.sql
    fi
}

sync_files(){
    for DIR in $(ls /var/www/MISP/app/files.dist); do
        rsync -azh --delete "/var/www/MISP/app/files.dist/$DIR" "/var/www/MISP/app/files/"
    done
}

# Ensure SSL certs are where we expect them, for backward comparibility See issue #53
for CERT in cert.pem dhparams.pem key.pem; do
    echo "/etc/nginx/certs/$CERT /etc/ssl/certs/$CERT"
    if [[ ! -f "/etc/nginx/certs/$CERT" && -f "/etc/ssl/certs/$CERT" ]]; then
        WARNING53=true
        cp /etc/ssl/certs/$CERT /etc/nginx/certs/$CERT
    fi
done

# Things we should do when we have the INITIALIZE Env Flag
if [[ "$INIT" == true ]]; then
    echo "Setup MySQL..." && init_mysql
    echo "Setup MISP files dir..." && init_misp_files
    echo "Ensure SSL certs exist..." && init_ssl
fi

# Things that should ALWAYS happen
echo "Configure Cake | Change Redis host to $REDIS_FQDN ... " && setup_cake_config

# Things we should do if we're configuring MISP via ENV
echo "Configure MISP | Initialize misp base config..." && init_misp_config

echo "Configure MISP | Sync app files..." && sync_files

echo "Configure MISP | Enforce permissions ..."
echo "... chown -R www-data.www-data /var/www/MISP ..." && find /var/www/MISP -not -user www-data -exec chown www-data.www-data {} +
echo "... chmod -R 0750 /var/www/MISP ..." && find /var/www/MISP -perm 550 -type f -exec chmod 0550 {} + && find /var/www/MISP -perm 770 -type d -exec chmod 0770 {} +
echo "... chmod -R g+ws /var/www/MISP/app/tmp ..." && chmod -R g+ws /var/www/MISP/app/tmp
echo "... chmod -R g+ws /var/www/MISP/app/files ..." && chmod -R g+ws /var/www/MISP/app/files
echo "... chmod -R g+ws /var/www/MISP/app/files/scripts/tmp ..." && chmod -R g+ws /var/www/MISP/app/files/scripts/tmp

# Work around https://github.com/MISP/MISP/issues/5608
if [[ ! -f /var/www/MISP/PyMISP/pymisp/data/describeTypes.json ]]; then
    mkdir -p /var/www/MISP/PyMISP/pymisp/data/
    ln -s /usr/local/lib/python3.7/dist-packages/pymisp/data/describeTypes.json /var/www/MISP/PyMISP/pymisp/data/describeTypes.json
fi

if [[ ! -L "/etc/nginx/sites-enabled/misp80" && "$NOREDIR" == true ]]; then
    echo "Configure NGINX | Disabling Port 80 Redirect"
    ln -s /etc/nginx/sites-available/misp80-noredir /etc/nginx/sites-enabled/misp80
elif [[ ! -L "/etc/nginx/sites-enabled/misp80" ]]; then
    echo "Configure NGINX | Enable Port 80 Redirect"
    ln -s /etc/nginx/sites-available/misp80 /etc/nginx/sites-enabled/misp80
else
    echo "Configure NGINX | Port 80 already configured"
fi

if [[ ! -L "/etc/nginx/sites-enabled/misp" && "$SECURESSL" == true ]]; then
    echo "Configure NGINX | Using Secure SSL"
    ln -s /etc/nginx/sites-available/misp-secure /etc/nginx/sites-enabled/misp
elif [[ ! -L "/etc/nginx/sites-enabled/misp" ]]; then
    echo "Configure NGINX | Using Standard SSL"
    ln -s /etc/nginx/sites-available/misp /etc/nginx/sites-enabled/misp
else
    echo "Configure NGINX | SSL already configured"
fi

if [[ ! "$SECURESSL" == true && ! -f /etc/nginx/certs/dhparams.pem ]]; then
    echo "Configure NGINX | Building dhparams.pem"
    openssl dhparam -out /etc/nginx/certs/dhparams.pem 2048
fi

if [[ "$DISIPV6" == true ]]; then
    echo "Configure NGINX | Disabling IPv6"
    sed -i "s/listen \[\:\:\]/\#listen \[\:\:\]/" /etc/nginx/sites-enabled/misp80
    sed -i "s/listen \[\:\:\]/\#listen \[\:\:\]/" /etc/nginx/sites-enabled/misp
fi

if [[ -x /custom-entrypoint.sh ]]; then
    /custom-entrypoint.sh
fi

# delete pid file
[ -f $ENTRYPOINT_PID_FILE ] && rm $ENTRYPOINT_PID_FILE

if [[ "$WARNING53" == true ]]; then
    echo "WARNING - WARNING - WARNING"
    echo "The SSL certs have moved. You currently have them mounted to /etc/ssl/certs."
    echo "This needs to be changed to /etc/nginx/certs."
    echo "See: https://github.com/coolacid/docker-misp/issues/53"
    echo "WARNING - WARNING - WARNING"
fi 

# Start NGINX
nginx -g 'daemon off;'
