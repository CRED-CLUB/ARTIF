#!/bin/bash

# Wait until entrypoint apache is ready
while (true)
do
    sleep 2
    [ -f /entrypoint_apache.install ] && continue
    break
done

while true
do
    echo "Start Workers..."
    sudo -u www-data /var/www/MISP/app/Console/worker/start.sh
    echo "Start Workers...finished"
    sleep 3600
done
