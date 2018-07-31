#!/usr/bin/env python
# Fabian Lagos - flagos@itsec.cl
# -*- coding: utf-8 -*-

import stuffs
import subprocess

SslPATH = "/opt/waf/nginx/etc/ssl/"
ProdNginxAvail = '/opt/waf/nginx/etc/sites-available/'

@auth.requires_login()
def SaveCerts():


    a = stuffs.Filtro()
    b = a.CheckStr(request.vars['id'])

    if b != 'YES':
        return


    query = db(db.production.id_rand == request.vars['id']).select(db.production.nginx_conf_data, db.production.app_name)

    aux = SslPATH + query[0]['app_name']
    try:


        f = open('%s%s/cert_check.pem.chain' %(SslPATH, query[0]['app_name']), 'w')
        f.write(request.vars['cert'])
        f.close()

        f = open('%s%s/privkey_check.pem' %(SslPATH, query[0]['app_name']), 'w')
        f.write(request.vars['key'])
        f.close()

        if request.vars['chain']:
            f = open('%s%s/cert_check.pem.chain' %(SslPATH, query[0]['app_name']), 'a')
            f.write('\n')
            f.write(request.vars['chain'])
            f.close()

        check_process = subprocess.Popen(['openssl','x509', '-in', aux + '/cert_check.pem.chain'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check, err = check_process.communicate()

        if err:
            rm_cert = subprocess.Popen(['rm', aux + '/cert_check.pem.chain'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            rm_privkey = subprocess.Popen(['rm', aux + '/privkey_check.pem'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response.flash = err
            return

        check_process = subprocess.Popen(['openssl','rsa', '-check', '-in', aux + '/privkey_check.pem', '-noout'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check, err = check_process.communicate()

        if err:
            rm_cert = subprocess.Popen(['rm', aux + '/cert_check.pem.chain'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            rm_privkey = subprocess.Popen(['rm', aux + '/privkey_check.pem'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response.flash = err
            return

        mv_cert = subprocess.Popen(['mv', aux + '/cert_check.pem.chain', aux + '/cert.pem.chain'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        mv_priv = subprocess.Popen(['mv', aux + '/privkey_check.pem', aux + '/privkey.pem'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        db.certificate.update_or_insert(db.certificate.id_rand == request.vars['id'],
                           id_rand=request.vars['id'],
                           cert=request.vars['cert'],
                           chain=request.vars['chain'],
                           privkey=request.vars['key'],
                           protocol=['checked','checked','checked'],
                           prefer_cipher='checked',
                           ciphers='EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH'
                           )



    except Exception as e:
        response.flash = e

    #print query[0]['nginx_conf_data']
    response.flash = "Certificate saved"
    return

@auth.requires_login()
def SaveProtocols():
    import changeconfig

    a = stuffs.Filtro()
    b = a.CheckStr(request.vars['id'])

    if b != 'YES':
        return

    query = db(db.production.id_rand == request.vars['id']).select(db.production.nginx_conf_data, db.production.app_name)

    text = ""
    array = ['unchecked', 'unchecked', 'unchecked']

    if request.vars['1'] == "true":
        text = text + " TLSv1"
        array[0] = 'checked'
    if request.vars['2'] == "true":
        text = text + " TLSv1.1"
        array[1] = 'checked'

    if request.vars['3'] == "true":
        text = text + " TLSv1.2"
        array[2] = 'checked'

    if text == "":
        response.flash = "Error"
        return

    #print array

    text = text + ";"

    try:
        change = changeconfig.Change()
        r = change.Text(query[0]['nginx_conf_data'], 'ssl_protocols', "        ssl_protocols%s" %(text))

        DataNginx = '\n'.join(r['new_list'])
        AppName = query[0]['app_name']
        UpdateFiles = stuffs.CreateFiles()
        UpdateFiles.CreateNginxFiles(ProdNginxAvail, AppName, DataNginx)
        u = stuffs.Nginx()
        u.Reload()
        db.certificate.update_or_insert(db.certificate.id_rand == request.vars['id'],
                               protocol=array)
        db(db.production.id_rand == request.vars['id']).update(nginx_conf_data='\n'.join(r['new_list']))


    except Exception as e:
        response.flash = e
        return

    response.flash = "Changed Protocol SSL"


    return

@auth.requires_login()
def CipherPrefer():
    import changeconfig

    a = stuffs.Filtro()
    b = a.CheckStr(request.vars['id'])

    if b != 'YES':
        return

    query = db(db.production.id_rand == request.vars['id']).select(db.production.nginx_conf_data, db.production.app_name)

    text = ""

    if request.vars['status'] == "On":
        text = text + " on"
        db.certificate.update_or_insert(db.certificate.id_rand == request.vars['id'],
                           prefer_cipher="checked")

    elif request.vars['status'] == "Off":
        text = text + " off"
        db.certificate.update_or_insert(db.certificate.id_rand == request.vars['id'],
                           prefer_cipher="unchecked")

    else:
        response.flash = "Error"
        return

    text = text + ";"

    try:

        change = changeconfig.Change()
        r = change.Text(query[0]['nginx_conf_data'], 'ssl_prefer_server_ciphers', "        ssl_prefer_server_ciphers%s" %(text))

        DataNginx = '\n'.join(r['new_list'])
        AppName = query[0]['app_name']
        UpdateFiles = stuffs.CreateFiles()
        UpdateFiles.CreateNginxFiles(ProdNginxAvail, AppName, DataNginx)
        u = stuffs.Nginx()
        u.Reload()
        db(db.production.id_rand == request.vars['id']).update(nginx_conf_data='\n'.join(r['new_list']))

    except Exception as e:
        response.flash = e
        return

    response.flash = "Changed SSL prefer server ciphers SSL"

    return

@auth.requires_login()
def SavedCipher():

    import changeconfig

    a = stuffs.Filtro()
    b = a.CheckStr(request.vars['id'])

    if b != 'YES':
        response.flash = "Error"
        return

    if any(c in str(request.vars['ciphers']) for c in "\"/',%#$=*()[]{}?¿|&<>¨~°^ ."):
        response.flash = "Error"
        return

    query = db(db.production.id_rand == request.vars['id']).select(db.production.nginx_conf_data, db.production.app_name)
    text = request.vars['ciphers']
    text2 = "'" + text + "';"

    try:
        change = changeconfig.Change()
        r = change.Text(query[0]['nginx_conf_data'], 'ssl_ciphers', "        ssl_ciphers %s" %(text2))

        DataNginx = '\n'.join(r['new_list'])
        AppName = query[0]['app_name']
        UpdateFiles = stuffs.CreateFiles()
        UpdateFiles.CreateNginxFiles(ProdNginxAvail, AppName, DataNginx)
        u = stuffs.Nginx()
        u.Reload()
        db.certificate.update_or_insert(db.certificate.id_rand == request.vars['id'],
                                            ciphers=text)
        db(db.production.id_rand == request.vars['id']).update(nginx_conf_data='\n'.join(r['new_list']))

    except Exception as e:
        response.flash = e
        return

    response.flash = "Changed SSL Cipher"
    return
