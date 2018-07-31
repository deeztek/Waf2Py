#!/usr/bin/env python
#@author: chris cvaras@itsec.cl
# -*- coding: utf-8 -*-
#

import subprocess
import stuffs


class Network:
    def __init__(self):
        pass
    
    def IpsUsed(self):
        
        #Get all Ips used from all interfaces
        #for debian 8
        cmd = "/sbin/ifconfig | grep encap -1 | awk '{print $1,$2}' | sed 's/--/-----------------------------------------------/g'"
        self.process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.sum, self.sum_err = self.process.communicate()
        if self.sum == "":
            #for debian 9

            cmd = "/sbin/ifconfig | grep  mtu -1 | awk '{print $1,$2}' | sed 's/--/<-------------------------------------------------->/g'"
            self.process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.sum, self.sum_err = self.process.communicate()

        
        return self.sum.splitlines()
    
    def Interfaces(self, iface):
        #list all interfaces
        self.iface = iface
        self.process = subprocess.Popen(['ip', 'addr', 'show', 'dev', '%s' %(self.iface)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        interfaces,error = process.communicate()
        
        return interfaces
    
    def AddIface(self,iface_ip, netmask, iface_name):
        self.iface_name = iface_name
        self.netmask = netmask
        self.iface_ip = iface_ip
        #get main ip
        #for debian 8
        cmd = "/sbin/ifconfig | head -n2 |grep 'inet addr:' | awk '{print $2}' | cut -d ':' -f2"
        self.process3 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.out3, self.err3 = self.process3.communicate()

        if self.out3 == "":
            print 'debian 9'
            #for debian 9
            cmd = "/sbin/ifconfig | head -n2 |grep 'inet ' | awk '{print $2}' | cut -d ':' -f2"
            self.process3 = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.out3, self.err3 = self.process3.communicate()

        self.out3 = self.out3.replace('\n', '')
        
        if self.iface_ip in self.out3:
            message = 'This ip is reserved for Me!'
            self.name = None
            pass
        else:
            import sqlite3
            con = sqlite3.connect('/home/www-data/waf2py_community/applications/Waf2Py/databases/waf2py.sqlite')
            c = con.cursor()
            c.execute('SELECT number FROM n_interfaces')
            fetch = c.fetchone()
            n_iface = fetch[0]
            n_iface = int(n_iface)+1
            #update the numbers of virtual interfaces
            c.execute('UPDATE n_interfaces SET number = %s' %n_iface)
            con.commit()
            con.close()
            self.name = str(self.iface_name) + ':' + str(n_iface)

            #Add interface
            self.process2 = subprocess.Popen(['sudo', '/sbin/ifconfig', str(self.name), str(self.iface_ip), 'netmask', str(self.netmask)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.out, self.err = self.process2.communicate()
            message = 'Interface Added'

        return dict(message=message, device=self.name)

    def iface_names(self):
        #for debian 8
        cmd = "/sbin/ifconfig | grep 'Link encap' |awk '{print $1}' | sed 's/:.*//g' | sort -u | sed 's/lo//g' |sed '/^$/d'"
        self.process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.ifaces, self.err = self.process.communicate()
        print self.ifaces
        if self.ifaces == "":
            #for debian 9
            cmd = "/sbin/ifconfig | grep 'mtu' |awk '{print $1}' | sed 's/:.*//g' | sort -u | sed 's/lo//g' |sed '/^$/d'"
            self.process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.ifaces, self.err = self.process.communicate()
            print self.ifaces

        return self.ifaces
