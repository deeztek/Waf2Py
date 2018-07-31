#!/usr/bin/env python
# Chris - cvaras@itsec.cl
# -*- coding: utf-8 -*-

import sqlite3
import os
import subprocess
import random
import string

conn = sqlite3.connect('/home/www-data/waf2py_community/applications/Waf2Py/databases/waf2py.sqlite')
con = conn.cursor()

a = con.execute('SELECT app_name,id_rand FROM production')
b = a.fetchall()
chars = string.letters + string.digits
pwdSize = 30

result = ''.join((random.choice(chars)) for x in range(pwdSize))
for row in b:
    #print row[1]
    rand = ''.join((random.choice(chars)) for x in range(pwdSize))
    con.execute('DELETE FROM logs_file WHERE id_rand = "%s"' %(row[1]))
    #con.execute('SELECT id_rand FROM production WHERE app_name = "%s"' %(row[0]))
    ##id_rand = con.fetchone()[0]
    #print id_rand
    #print 'here'
    os.chdir('/opt/waf/nginx/var/log/'+row[0])
    cmd = "ls -lhgG --time-style=iso *.gz | awk '{print $3,$4,$6}'"
    #os.system('pwd')
    out1 = subprocess.Popen(cmd, shell=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    msg = out1.communicate()[0]
    for i in msg.splitlines():
        logs = i.split(" ")
        #print logs
        print logs[2]
        if 'access' in logs[2]:
            log_type = 'Access'
        elif 'error' in logs[2]:
            log_type = 'Error'
        elif 'debug' in logs[2]:
            log_type = 'Debug'
        print logs
        id_rand2 = log_type+rand
        con.execute('INSERT INTO logs_file (id_rand, log_name, type, size, date, id_rand2) VALUES ("%s","%s","%s", "%s", "%s", "%s")'
                    %(row[1], logs[2], log_type, logs[0], logs[1], id_rand2))
conn.commit()        
conn.close()
