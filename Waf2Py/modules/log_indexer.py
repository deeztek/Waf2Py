#Created by Chris - cvaras@itsec.cl
#
#This file run with a crontab every 5 minutes or more indexing in db2 access logs, attack_logs, debug logs,
#After the index removes the request that are not an attack in audit logs folder.


import subprocess

#Index access logs

#Error Logs
cmd3 = 'tac /opt/waf/nginx/var/log/'+query[0]['app_name']+'/'+query[0]['app_name']+'_debug.log | head -300'
out3 = subprocess.Popen(cmd3, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
msg3, err3 = out3.communicate()