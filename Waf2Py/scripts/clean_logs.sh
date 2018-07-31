#!/bin/bash

#remove files not containing an attack
 
#get year
year=$(date|awk {'print $6'})
d=$(date)
cd /home/www-data/waf2py_community/applications/Waf2Py/scripts/
/usr/bin/python /home/www-data/waf2py_community/applications/Waf2Py/scripts/get_apps.py
echo "$d - Starting logs cleaning" >> /home/www-data/waf2py_community/applications/Waf2Py/scripts/cleaning.log
for x in $(cat names);
    do
    echo "Cleaning not usefull logs for: "$x >> /home/www-data/waf2py_community/applications/Waf2Py/scripts/cleaning.log
    cd "/opt/waf/nginx/var/log/"$x"/audit_logs/"
    #delete log files which are not an attack
    logs_count=$(grep -RL "\[id \"" * | wc -l)
    echo "$logs_count logs removed because their are ligitimal request" >> /home/www-data/waf2py_community/applications/Waf2Py/scripts/cleaning.log
    grep -RL "\[id \"" * | while read i; do rm -r $i; done
    done
echo "Logs cleaned" >> /home/www-data/waf2py_community/applications/Waf2Py/scripts/cleaning.log
echo "Reloading nginx" >> /home/www-data/waf2py_community/applications/Waf2Py/scripts/cleaning.log
/usr/bin/python /home/www-data/waf2py_community/applications/Waf2Py/modules/manual_reload.py
cd
