#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3
import subprocess
import time


# Create connection into DB

con = sqlite3.connect('/home/www-data/waf_admin/applications/WAF/databases/waf2py.sqlite')
cur = con.cursor()

cur.execute("SELECT app_name FROM production")
apps = cur.fetchone()

print apps

for name in apps:
    #get rotation_id
    cur.execute("SELECT log_rotation_id FROM production WHERE app_name = name")
    rotation_id = cur.fetchone()
    
    subprocess.Popen(['mv', '/opt/waf/nginx/var/log/'+str(name)+'/'+str(name)+'_access.log', '/opt/waf/nginx/var/log/'+str(name)+'/'+str(name)+'_access.log.'+rotation_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.Popen(['mv', '/opt/waf/nginx/var/log/'+str(name)+'/'+str(name)+'_error.log', '/opt/waf/nginx/var/log/'+str(name)+'/'+str(name)+'_error.log.'+rotation_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.Popen(['mv', '/opt/waf/nginx/var/log/'+str(name)+'/'+str(name)+'_debug.log', '/opt/waf/nginx/var/log/'+str(name)+'/'+str(name)+'_error.log.'+rotation_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process = subprocess.Popen(['cat', '/opt/waf/nginx/var/run/nginx.pid'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pid = process.comunicate(0)
    subprocess.Popen(['kill', '-USR1', pid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1)
    #compress access log
    subprocess.Popen(['tar', '-cvzf', '/opt/waf/nginx/var/log/'+str(name)+'/'+str(name)+'_access.log.'+rotation_id+'.tar.gz', '/opt/waf/nginx/var/log/'+str(name)+'/'+str(name)+'_access.log.'+rotation_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #compress error log
    subprocess.Popen(['tar', '-cvzf', '/opt/waf/nginx/var/log/'+str(name)+'/'+str(name)+'_error.log.'+rotation_id+'.tar.gz', '/opt/waf/nginx/var/log/'+str(name)+'/'+str(name)+'_error.log.'+rotation_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    

