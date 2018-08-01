#!/usr/bin/env bash

echo "[+]Installing some deps"
apt-get -y install net-tools #Only for Debian 9
apt-get -y install apache2 sudo zip unzip wget build-essential tar libapache2-mod-wsgi libtool m4 automake apache2-dev libpcre3 libpcre3-dev libxml2-dev zlib1g-dev geoip-bin libgeoip-dev

echo "[+]Creating www-data home folder and download web2py framework"

mkdir /home/www-data
current_dir=$(pwd)
cd /home/www-data
rm web2py_src.zip*
wget http://web2py.com/examples/static/web2py_src.zip
unzip web2py_src.zip
mv web2py waf2py_community
mv /home/www-data/waf2py_community/handlers/wsgihandler.py /home/www-data/waf2py_community/wsgihandler.py
cd $current_dir
mv Waf2Py /home/www-data/waf2py_community/applications/
clear
echo "[+]Creating  ssl folder and deleting enabled default sites of apache"

rm /etc/apache2/sites-enabled/*.conf
mkdir /etc/apache2/ssl
cd /etc/apache2/
mv /etc/apache2/ports.conf /etc/apache2/ports.conf.bkp

echo "[+]Configuring ports"

echo '
#Created by waf2Py script
<IfModule ssl_module>
	#Listen 443
	Listen 62443
</IfModule>

<IfModule mod_gnutls.c>
	Listen 443
</IfModule>
' > /etc/apache2/ports.conf

echo "[+]Enable apache modules"
a2enmod ssl
a2enmod proxy
a2enmod proxy_http
a2enmod headers
a2enmod expires
a2enmod wsgi
clear


echo "[+]Creating apache config"
echo '
<VirtualHost *:62443>
  #SSL certs
  SSLEngine on
  SSLCertificateFile /etc/apache2/ssl/self_signed.cert
  SSLCertificateKeyFile /etc/apache2/ssl/self_signed.key

  WSGIDaemonProcess Waf2Py user=www-data group=www-data
  WSGIProcessGroup Waf2Py
  WSGIScriptAlias / /home/www-data/waf2py_community/wsgihandler.py
  WSGIPassAuthorization On


<Location /admin>
  Require all granted
  #Comment line above and uncomment lines below to restrict access to the admin interfaces of web2py (Totally recommended):
  #Require ip X.X.X.X
  #Require all denied
  </Location>

  <LocationMatch ^/([^/]+)/appadmin>
    Require all granted
    #Comment line above and uncomment lines below to restrict access to the admin interfaces of web2py (Totally recommended):
    #Require ip X.X.X.X
    #Require all denied
  </LocationMatch>

  <Directory /home/www-data/waf2py_community>
    AllowOverride None
    Require all granted
    #Comment line above and uncomment lines below to restrict access to the waf2py app:
    #Require ip X.X.X.X
    #Require all denied

    <Files wsgihandler.py>
       Require all granted
       #Comment line above and uncomment lines below to restrict access to the waf2py app:
       #Require ip X.X.X.X
       #Require all denied
    </Files>
  </Directory>

  AliasMatch ^/([^/]+)/static/(?:_[\d]+.[\d]+.[\d]+/)?(.*) \
        /home/www-data/waf2py_community/applications/$1/static/$2

  <Directory /home/www-data/waf2py_community/applications/*/static/>
    Options -Indexes
    ExpiresActive On
    ExpiresDefault "access plus 1 hour"
    Require all granted
    #Comment line above and uncomment lines below to restrict access to the static content:
    #Require ip X.X.X.X
    #Require all denied
  </Directory>


  #Access and error logs files
  CustomLog /var/log/apache2/waf2py_access.log common
  ErrorLog /var/log/apache2/waf2py_error.log

</VirtualHost> ' > /etc/apache2/sites-available/waf2py.conf

echo "[+]Enabling Waf2Py on apache"
cd /etc/apache2/sites-enabled
ln -s ../sites-available/waf2py.conf .


echo "[+]Creating ssl certificates"

cd /etc/apache2/ssl
openssl genrsa 4096 > /etc/apache2/ssl/self_signed.key
chmod 400 /etc/apache2/ssl/self_signed.key
openssl req -new -x509 -nodes -sha1 -days 365 -key /etc/apache2/ssl/self_signed.key > /etc/apache2/ssl/self_signed.cert
openssl x509 -noout -fingerprint -text < /etc/apache2/ssl/self_signed.cert > /etc/apache2/ssl/self_signed.info
clear





chown -R www-data:www-data /home/www-data/waf2py_community
echo "[+]Change the admin password for the admin interface of web2py"
cd /home/www-data/waf2py_community
sudo -u www-data python -c "from gluon.widget import console; console();"
sudo -u www-data python -c "from gluon.main import save_password; save_password(raw_input('Choose an admin password for web2py admin: '),62443)"
cd ../

#remove default applications
rm -r /home/www-data/waf2py_community/applications/examples
rm -r /home/www-data/waf2py_community/applications/welcome



echo "[+]Adding user www-data to sudo"
adduser www-data sudo
echo '
www-data ALL=(ALL) NOPASSWD: /opt/waf/nginx/sbin/nginx
www-data ALL=(ALL) NOPASSWD: /bin/netstat
www-data ALL=(ALL) NOPASSWD: /bin/chmod
www-data ALL=(ALL) NOPASSWD: /bin/chown
www-data ALL=(ALL) NOPASSWD: /sbin/ifconfig
www-data ALL=(ALL) NOPASSWD: /sbin/route
' >> /etc/sudoers

cd $current_dir

debian_version=$(cat /etc/issue | grep "Debian" | awk '{print $3}')
if [ $debian_version == '8' ]
    then
        mv waf_core_debian_8.tar.gz /opt/
        cd /opt/
        tar xvzf waf_core_debian_8.tar.gz
else
    mv waf_core_debian_9.tar.gz /opt/
    cd /opt/
    tar xvzf waf_core_debian_9.tar.gz
fi
cd $current_dir
clear
echo "[+] Creating cronjobs"

mkdir /etc/crons_waf
echo '
#!/bin/sh

test -x /usr/sbin/logrotate || exit 0
/usr/sbin/logrotate /etc/logrotate.conf
' > /etc/crons_waf/logrotate

#write out current crontab
crontab -l > waf_cron
#echo new cron into cron file
echo '@reboot  /usr/bin/python /home/www-data/waf2py_community/applications/Waf2Py/scripts/check_services.py
2 0 * * * /usr/bin/python /home/www-data/waf2py_community/applications/Waf2Py/scripts/index_logs_files.py
0 */2 * * * /bin/bash /home/www-data/waf2py_community/applications/Waf2Py/scripts/remove_tmp.sh
0 */2 * * * /bin/bash /home/www-data/waf2py_community/applications/Waf2Py/scripts/clean_logs.sh
1 0 * * * /bin/bash /etc/crons_waf/logrotate' >> waf_cron
#install new cron file
crontab waf_cron
rm waf_cron


echo "[+]Creating routes file"
echo "
routers = dict(
    BASE = dict(
        default_application='Waf2Py'
    )
)
"> /home/www-data/waf2py_community/routes.py
mkdir /home/www-data/waf2py_community/logrotation.d
chown -R www-data:www-data /home/www-data/waf2py_community/*
/etc/init.d/apache2 restart

echo "[+]Done!"
echo "[++]Now go to https://yourip:62443/Waf2Py and login"
echo "[++]User: admin"
echo "[++]Pass: admin"
echo "[++]Please don't forget to change the default password"
echo "Note: Before you go public on internet, check /etc/apache2/sites-enabled/waf2py.conf and looks for lines 'Require ip x.x.x.x', make sure to put your ips there to avoid any other unwanted 'user' trying to access to this interface"


