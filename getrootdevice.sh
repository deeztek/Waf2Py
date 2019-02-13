rootdevice=$(/bin/mount|grep ' / '|cut -d' ' -f 1)
/bin/df -h | /bin/grep $rootdevice | awk '{print $1,$2,$3,$4,$5}'
