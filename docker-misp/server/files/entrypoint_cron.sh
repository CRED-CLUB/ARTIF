#!/bin/bash

# Create the misp cron tab
cat << EOF > /etc/cron.d/misp
20 2 * * * www-data /var/www/MISP/app/Console/cake Server cacheFeed "$CRON_USER_ID" all >/tmp/cronlog 2>/tmp/cronlog
30 2 * * * www-data /var/www/MISP/app/Console/cake Server fetchFeed "$CRON_USER_ID" all >/tmp/cronlog 2>/tmp/cronlog

00 3 * * * www-data /var/www/MISP/app/Console/cake Admin updateGalaxies >/tmp/cronlog 2>/tmp/cronlog
10 3 * * * www-data /var/www/MISP/app/Console/cake Admin updateTaxonomies >/tmp/cronlog 2>/tmp/cronlog
20 3 * * * www-data /var/www/MISP/app/Console/cake Admin updateWarningLists >/tmp/cronlog 2>/tmp/cronlog
30 3 * * * www-data /var/www/MISP/app/Console/cake Admin updateNoticeLists >/tmp/cronlog 2>/tmp/cronlog
45 3 * * * www-data /var/www/MISP/app/Console/cake Admin updateObjectTemplates >/tmp/cronlog 2>/tmp/cronlog

EOF

if [ ! -z "$SYNCSERVERS" ];
then
    TIME=0
    for SYNCSERVER in $SYNCSERVERS
    do
cat << EOF >> /etc/cron.d/misp
$TIME 0 * * * www-data /var/www/MISP/app/Console/cake Server pull "$CRON_USER_ID" "$SYNCSERVER">/tmp/cronlog 2>/tmp/cronlog
$TIME 1 * * * www-data /var/www/MISP/app/Console/cake Server push "$CRON_USER_ID" "$SYNCSERVER">/tmp/cronlog 2>/tmp/cronlog
EOF

    ((TIME+=5))
    done
fi

# Build a fifo buffer for the cron logs, 777 so anyone can write to it
if [[ ! -p /tmp/cronlog ]]; then
    mkfifo /tmp/cronlog
fi
chmod 777 /tmp/cronlog

cron -f | tail -f /tmp/cronlog
