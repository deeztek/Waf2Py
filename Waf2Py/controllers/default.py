#!/usr/bin/env python
# Chris - cvaras@itsec.cl
# -*- coding: utf-8 -*-

import stuffs
import changeconfig
from logs import *
import subprocess
import network

# Define Paths Tmp
TmpNginxAvailable = '/opt/waf/nginx/etc/tmp/sites-available/'
TmpNginxEnabled = '/opt/waf/nginx/etc/tmp/sites-enabled/'
TmpModsecConf = '/opt/waf/nginx/etc/tmp/modsecurity_conf/'
TmpModsecRules = '/opt/waf/nginx/etc/tmp/modsec_rules/'
BackendTmp = '/opt/waf/nginx/etc/tmp/backend/'
TmpListenPATH = '/opt/waf/nginx/etc/tmp/listen/'

# Define Paths Production
ProdNginxEnabled = '/opt/waf/nginx/etc/sites-enabled/'
ProdNginxAvail = '/opt/waf/nginx/etc/sites-available/'
ProdModsecConf = '/opt/waf/nginx/etc/modsecurity_conf/'
ProdModsecRules = '/opt/waf/nginx/etc/modsec_rules/'
BackendProd = '/opt/waf/nginx/etc/backend/'
LogsPATH = '/opt/waf/nginx/var/log/'
ListenPATH = '/opt/waf/nginx/etc/listen/'
SslPATH = "/opt/waf/nginx/etc/ssl/"
DenyPathsDir = '/opt/waf/nginx/etc/rewrite/paths/'

# Define rules
Xss = 'modsecurity_crs_41_xss_attacks.conf'
Sqli = 'modsecurity_crs_41_sql_injection_attacks.conf'
Generic = 'modsecurity_crs_40_generic_attacks.conf'
ProtoAnomalies = 'modsecurity_crs_21_protocol_anomalies.conf'
ProtoViolations = 'modsecurity_crs_20_protocol_violations.conf'


@auth.requires_login()
def index():
    return dict(page="Welcome", icon="", title="")

def user():
    session.enabled = 'active'
    session.disabled = ''
    session.e_expanded = 'true'
    session.d_expanded = 'false'
    return dict(form=auth())

@auth.requires_login()
def Dashboard():
    import subprocess

    #disk usage
    cmd_disk = "/bin/df -h | /bin/grep sda1 | awk '{print $1,$2,$3,$4,$5}'"
    out1 = subprocess.Popen(cmd_disk, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    disk, disk_err = out1.communicate()
    disk_info = {}
    info = disk.split()
    disk_info['volume'] = info[0]
    disk_info['total'] = info[1]
    disk_info['used'] = info[2]
    disk_info['free'] = info[3]
    disk_info['percent'] = info[4]

    #RAM usage
    cmd_ram = "/usr/bin/free -m | sed 's/-\/+ buffers\/cache:.*//g' | sed /^$/d | /usr/bin/awk '{print $1,$2,$3,$4}' | /usr/bin/tail -2"
    out2 = subprocess.Popen(cmd_ram, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ram, ram_err = out2.communicate()
    ram_info = {}
    ram = ram.split()
    ram_info['ram_total'] = ram[1]
    ram_info['ram_used'] = ram[2]
    ram_info['ram_free'] = ram[3]
    ram_info['swap_total'] = ram[5]
    ram_info['swap_used'] = ram[6]
    ram_info['swap_free'] = ram[7]

    summary_logs = db2(db2.defend_log_summary).select()

    apps_usage = {}
    for i in summary_logs:
        apps_usage[i['app_name']] = i['requests']

    return dict(page="Dashboard", icon="fa fa-bar-chart", title="", disk=disk_info, ram=ram_info, summary_logs=summary_logs, apps_usage=apps_usage)

@auth.requires_login()
def base():
    grid = SQLFORM.grid(db.basic_conf, csv=False, searchable=False)

    return dict(grid=grid)

@auth.requires_login()
def reload():
    from stuffs import Nginx
    a = Nginx()
    r = a.Reload()
    #print r
    return r


@auth.requires_login()
def start():
    from stuffs import Nginx
    a = Nginx()
    r = a.Start()
    return r

@auth.requires_login()
def stop():

    s = stuffs.Nginx()
    r = s.Stop()
    return r

@auth.requires_login()
def check():

    s = stuffs.Nginx()
    r = s.SyntaxCheck()
    return r

@auth.requires_login()
def Manage():
    return dict(icon="mdi mdi-engine", page="Manage the Engine", title="Start/Reload/Stop the Engine")

@auth.requires_login()
def ProdEdit():

    a = stuffs.Filtro()
    b = a.CheckStr(request.args[0])
    if b == 'YES':
        query = db(db.production.id_rand == request.args[0]).select(db.production.nginx_conf_data,
                                                                db.production.modsec_conf_data,
                                                                db.production.id_rand,
                                                                db.production.app_name,
                                                                db.production.xss_filter,
                                                                db.production.sqli_filter,
                                                                db.production.generic_filter,
                                                                db.production.proto_violations_filter,
                                                                db.production.proto_anomalies_filter,
                                                                db.production.backend_ip_http,
                                                                db.production.backend_ip_https,
                                                                db.production.listen_ip,
                                                                db.production.ports_http,
                                                                db.production.ports_https,
                                                                db.production.extra_headers,
                                                                db.production.paths_denied,
                                                                )
        query2 = db(db.system).select(db.system.iface_ip, db.system.used_by)
        certificate = None
        if db(db.certificate.id_rand == request.args[0]).isempty() == False:
            certificate = db(db.certificate.id_rand == request.args[0]).select(db.certificate.cert,
                                                                                db.certificate.chain,
                                                                                db.certificate.privkey,
                                                                                db.certificate.protocol,
                                                                                db.certificate.prefer_cipher,
                                                                                db.certificate.ciphers)


        if query[0]['proto_anomalies_filter'] == 'ON':
            proto_a_status = 'checked'
        else:
            proto_a_status = ''

        if query[0]['proto_violations_filter'] == 'ON':
            proto_v_status = 'checked'
        else:
            proto_v_status = ''
        if query[0]['xss_filter'] == 'ON':
            xss_status = 'checked'
        else:
            xss_status = ''
        if query[0]['sqli_filter'] == 'ON':
            sqli_status = 'checked'
        else:
            sqli_status = ''
        if query[0]['generic_filter'] == 'ON':
            generic_status = 'checked'
        else:
            generic_status = ''
        #NewLogApp(db2, auth.user.username, "Edit app " + query[0]['app_name'])
    else:
        response.flash = 'Invalid ID'
        redirect(URL('Websites'))

    return dict(query=query, generic_status=generic_status,
                xss_status=xss_status, sqli_status=sqli_status,
                proto_v_status=proto_v_status, proto_a_status=proto_a_status, query2=query2,
                certificate=certificate, page="Edit Aplication", icon="fa fa-pencil", title="Modify the configuration")
#



@auth.requires_login()
def basic_conf():
    grid = SQLFORM.grid(db.basic_conf, csv=False)
    return dict(grid=grid)



@auth.requires_login()
def Websites():
    links = ((
            lambda row: TAG.a(' ', _href=URL('default', 'WafLogs/' + str(row.id_rand)), target="callback-command", _class='btn btn-link glyphicon glyphicon-search')),(
            lambda row: TAG.a(' ', _href=URL('default', 'CheckProd/' + str(row.id_rand)), target="callback-command", _class='btn btn-info glyphicon glyphicon-check')),
            (lambda row: TAG.a(' ', _href=URL('default', 'ProdEdit/' + str(row.id_rand)), target="callback-command", _class="btn btn-info glyphicon glyphicon-pencil")),
            (lambda row: TAG.a(' ', _href=URL('default', 'EnableApp/' + str(row.id_rand)), target="callback-command", _class="btn btn-success glyphicon glyphicon-play")),
            (lambda row: TAG.a(' ', _href=URL('default', 'DisableApp/' + str(row.id_rand)), target="callback-command", _class="btn btn-warning glyphicon glyphicon-stop")),
            (lambda row: TAG.a(' ', _href=URL('default', 'DeleteApp/' + str(row.id_rand)), target="callback-command", _class="btn btn-danger glyphicon glyphicon-trash")),
             )
    headers = {'production.app_name': 'Name'}
    fields = [db.production.app_name,db.production.listen_ip, db.production.autor, db.production.id_rand, db.production.enabled]
    # Disable some camps in grid
    db.production.id_rand.writable = False
    db.production.id_rand.readable = False
    db.production.id_rand.writable = False
    db.production.id_rand.readable = False
    grid = SQLFORM.grid(db.production, links=links, headers=headers, details=False,fields=fields,searchable=False, csv=False, create=False, editable=False, deletable=False)
    enabled_counter = db(db.production.enabled == 'Enabled').count()
    disabled_counter = db(db.production.enabled == 'Disabled').count()
    query = db(db.production).select(db.production.app_name, db.production.Name, db.production.app_name, db.production.backend_ip_http,
                                     db.production.backend_ip_https, db.production.listen_ip, db.production.mode, db.production.enabled, db.production.listening, db.production.id_rand)



    if enabled_counter <= disabled_counter:
        disabled_tab = 'active'
        disabled_exp = 'true'
        enabled_tab = ''
        enabled_exp = 'false'
    else:
        disabled_tab = ''
        disabled_exp = 'false'
        enabled_tab = 'active'
        enabled_exp = 'true'


    return dict(query=query, page="Websites", icon="fa fa-cloud", title="", enabled=enabled_counter, disabled=disabled_counter,
                disabled_tab=disabled_tab,disabled_exp=disabled_exp,enabled_exp=enabled_exp,enabled_tab=enabled_tab)




@auth.requires_login()
def DeleteApp():
    import os
    import subprocess
    import stuffs

    a = stuffs.Filtro()
    try:
        b = a.CheckStr(request.args[0])
    except:
        b = 'NO'

    if b == 'YES':

        query = db(db.production.id_rand == request.args[0]).select(db.production.app_name, db.production.vhost_id, db.production.listen_ip)
        # Remove symbolic links in /opt/waf/nginx/etc/sites-enabled/
        subprocess.Popen(['rm', ProdNginxEnabled + query[0]['app_name'] + '_nginx.conf'],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Remove sites in /opt/waf/nginx/etc/sites-available/
        subprocess.Popen(['rm', ProdNginxAvail + query[0]['app_name'] + '_nginx.conf'],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Remove modsecurity conf in /opt/waf/nginx/etc/modsecurity_conf/
        subprocess.Popen(['rm',  ProdModsecConf + query[0]['app_name'] + '_modsec.conf'],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Remove modsecurity conf in /opt/waf/nginx/etc/modsec_rules/ **not working****
        subprocess.Popen(['rm', '-r ', ProdModsecRules + query[0]['app_name']],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #this work
        os.system('rm -r %s%s' %(ProdModsecRules, query[0]['app_name']))

        #Remove Backend file
        subprocess.Popen(['rm', BackendProd + query[0]['app_name']+'.conf'],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #Remove Listen file
        subprocess.Popen(['rm', '-r', ListenPATH + query[0]['app_name']],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        #Remove Logs associated
        subprocess.Popen(['rm', '-r', LogsPATH + query[0]['app_name']],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        #Remove rewrite config associated
        subprocess.Popen(['rm', '-r', DenyPathsDir + query[0]['app_name']],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        #remove logrotation conf
        subprocess.Popen(['sudo', 'chown', 'www-data.www-data', '/home/www-data/waf2py_community/applications/Waf2Py/logrotation.d/%s.conf' %(query[0]['app_name'])], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.Popen(['rm', '/home/www-data/waf2py_community/applications/Waf2Py/logrotation.d/%s.conf' %(query[0]['app_name'])],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #Remove ssl folder associated
        subprocess.Popen(['rm', '-r', SslPATH + query[0]['app_name']],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        #delete entry in db
        db(db.production.id_rand == request.args[0]).delete()
        #delete logs
        db2(db2.defend_log_summary.id_rand == request.args[0]).delete()
        #update status of the virtual ips
        is_used = db(db.system.iface_ip == query[0]['listen_ip']).select(db.system.used_by)
        print 'row is ised: ', is_used
        if is_used:
            if is_used[0]['used_by'] == query[0]['app_name']:
                db(db.system.iface_ip == query[0]['listen_ip']).update(available='Available', used_by=None)
            else:
                is_used_update = is_used[0]['used_by'].replace(", " + query[0]['app_name'], "")
                is_used_update = is_used_update.replace(query[0]['app_name'] + ", ", "")
                is_used_update = is_used_update.replace(query[0]['app_name'], "")
                db(db.system.iface_ip == query[0]['listen_ip']).update(used_by=is_used_update)






        #reload nginx
        a = stuffs.Nginx()
        r = a.Reload()
        if r == "Reload Succesfull":
            resp = 'Application was'+ query[0]['app_name']  +'deleted'
            NewLogApp(db2, auth.user.username, 'Application was'+ query[0]['app_name']  +'deleted')
            NewLogApp(db2, auth.user.username, r)
        else:
            resp = r
        NewLogApp(db2, auth.user.username, "Delete app " + query[0]['app_name'])
        response.flash = resp
        session.disabled = ''
        session.d_expanded = 'false'
        session.enabled = 'active'
        session.e_expanded = 'true'
        redirect(URL('Websites'))

    else:
        redirect(URL('Websites'))

    return locals()


@auth.requires_login()
def CreateNewApp():

    try:
        if request.vars['app_url'] != '' and len(request.vars['app_url']) < 45 and  request.vars['name'] != '' and len(request.vars['name']) < 45:
            AppName = request.vars['app_url']
            # Check if url contains dangerous character
            if any(c in AppName for c in "\"/'\;,=%#$*()[]?¿¡{}:!|&<>¨~°^ "):
                NewLogError(db2, auth.user.username, "Add new app: Invalid characters in application URL")
                session.flash = 'Invalid characters found'
            # Check if name contains dangerous character
            elif any(c in request.vars['name'] for c in "\"/'\;,=%#$*()[]?¿¡{}:!|&<>¨~°^ "):
                NewLogError(db2, auth.user.username, "Add new app: Invalid characters in application Name")
                session.flash = 'Invalid characters found'


            elif AppName[-1] == '.':
                NewLogError(db2, auth.user.username, "Application url cannot end with dot(.)")
                session.flash = 'Application url cannot end with dot(.)'


            elif AppName.startswith('https:'):
                NewLogError(db2, auth.user.username, "Application url cannot start with https://")
                session.flash = 'Application url cannot start with https://'

            elif AppName.startswith('http:'):
                NewLogError(db2, auth.user.username, "Application url cannot start with http://")
                session.flash = 'Application url cannot start with http://'


            else:
                #check if app already exist in production
                query = db(db.production.app_name == AppName).select(db.production.app_name)
                if query:
                    session.flash = 'This Application Already Exist'
                #a = db(db.production).select(db.production.app_name)
                #b = db(db.new_app).select(db.new_app.app_name)
                #if a and b and (AppName in str(a[0]['app_name']) or AppName in str(b[0]['app_name'])):

                else:

                    # Get nginx and modsecurity default conf
                    query1 = db(db.basic_conf).select(db.basic_conf.nginx_data_conf)
                    query2 = db(db.basic_conf).select(db.basic_conf.modsec_data_conf)
                    DataNginx = query1[0]['nginx_data_conf']
                    DataModsec = query2[0]['modsec_data_conf']

                    # Get a ramdom string for id_rand parameter
                    a = stuffs.Stuffs()
                    b = a.password()


                    # Insert new app in BD
                    db.new_app.insert(app_name=AppName,
                                      nginx_conf_data=DataNginx,
                                      modsec_conf_data=DataModsec,
                                      autor=session['auth']['user']['username'],
                                      id_rand=b,
                                      checked=0,
                                      deployed=0,
                                      Name=request.vars['name']
                                      )
                    id_app = db(db.new_app.app_name == AppName).select(db.new_app.id)
                    db(db.new_app.id == id_app[0]['id']).update(vhost_id=id_app[0]['id'], plbsid_id=id_app[0]['id'], max_fails='1', fail_timeout='60')
                    #modify the configuration
                    lista_nginx = []
                    lista_modsec = []




                    #Modify nginx configuration with new parameters
                    try:
                        #Modify nginx configuration with new parameters
                        for line in DataNginx.splitlines():
                            lista_nginx.append(line)
                        for line in lista_nginx:
                            if "SrvName" in line:
                                index = lista_nginx.index(line)
                                x = AppName.replace("www.", "")
                                a = line.replace("SrvNameAlias", "%s" %(x))
                                b = a.replace("SrvName", "%s" %(AppName))
                                lista_nginx[index] = b
                            if "vhost_id" in line:
                                index = lista_nginx.index(line)
                                l = line.replace("vhost_id", "%s" %(id_app[0]['id']))
                                lista_nginx[index] = l
                            if "ModSecStatus" in line:
                                index = lista_nginx.index(line)
                                l = line.replace("ModSecStatus", "on")
                                lista_nginx[index] = l
                            if "plbsid_id" in line:
                                index = lista_nginx.index(line)
                                l = line.replace("plbsid_id", "%s" %(id_app[0]['id']))
                                lista_nginx[index] = l
                        db(db.new_app.app_name == AppName).update(nginx_conf_data = '\n'.join(lista_nginx))
                    except Exception as e:
                        NewLogError(db2, auth.user.username, str(e))
                        response.flash = e

                    #Modify modsecurity conf with new parameters
                    for line in DataModsec.splitlines():
                        lista_modsec.append(line)
                        for line in lista_modsec:

                            if "SrvName" in line:
                                index = lista_modsec.index(line)
                                a = line.replace("SrvName", "%s" %(AppName))
                                lista_modsec[index] = a
                            if "vhost_id" in line:
                                x = line.replace("vhost_id", "%s" %(str(id_app[0]['id'])))
                                lista_modsec[index] = x

                    db(db.new_app.app_name == AppName).update(modsec_conf_data = '\n'.join(lista_modsec))

                    #get modified config
                    data = db(db.new_app.app_name == AppName).select(db.new_app.nginx_conf_data,
                                                                    db.new_app.modsec_conf_data)
                    #Create Nginx default conf for new App
                    CreateNginx = stuffs.CreateFiles()
                    response = CreateNginx.CreateNginxFiles(TmpNginxAvailable, AppName, data[0]['nginx_conf_data'])

                    # Create Nginx symlink
                    CreateNginxLink = stuffs.CreateFiles()
                    response = CreateNginxLink.CreateNginxSymlink(TmpNginxAvailable, AppName, 'tmp')

                    #Create folders and rules for new app
                    CreateModsec = stuffs.CreateFiles()
                    response = CreateModsec.CreateModsecFiles(TmpModsecRules, AppName, TmpModsecConf, data[0]['modsec_conf_data'])

                    # Create symlinks from base_rules to enabled rules
                    CreateLinks = stuffs.CreateFiles()
                    response = CreateLinks.CreateSymlinksRules(TmpModsecRules, AppName)

                    subprocess.Popen(['mkdir', LogsPATH + '%s' %(AppName)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                    session.flash = 'App Created'
                    NewLogApp(db2, auth.user.username, "New Websites " + AppName)


        else:
            if len(request.vars['app_url']) > 45:
                session.flash = 'App Name too long'
                NewLogError(db2, auth.user.username, "Create app: App Name too long ")


            elif request.vars['app_url'] == '':
                session.flash = 'You must enter a name'
                NewLogError(db2, auth.user.username, "Create app: you must enter a name ")



    except Exception as e:
        NewLogError(db2, auth.user.username, str(e))
        session.flash = str(e)

    return redirect(URL('new_app'))


@auth.requires_login()
def CheckNewSyntax():

    c = stuffs.Filtro()
    d = c.CheckStr(request.args[0])
    if d == 'YES':

        # Run syntax check in nginx
        process = subprocess.Popen(['sudo','/opt/waf/nginx/sbin/nginx', '-t', '-c', '/opt/waf/nginx/etc/tmp/nginx.conf'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out,err = process.communicate()

        #show results in flash message
        if 'syntax is ok' in err:
            db(db.new_app.id_rand == request.args[0]).update(checked = 1)
            session.flash = 'Syntax OK'
            response = 'Syntax ok'
            redirect(URL('new_app'))

        else:
            db(db.new_app.id_rand == request.args[0]).update(checked = 0)
            session.flash = err
            response = 'Bad Syntax'
        redirect(URL('new_app'))
    else:
        redirect(URL('new_app'))
    return dict(response=response)


@auth.requires_login()
def deploy():
    import stuffs
    a = stuffs.Filtro()
    b = a.CheckStr(request.args[0])
    if b == 'YES':
        import subprocess
        import stuffs

        query = db(db.new_app.id_rand == request.args[0]).select(db.new_app.app_name,
                                                            db.new_app.nginx_conf_data,
                                                            db.new_app.modsec_conf_data,
                                                            db.new_app.autor,
                                                            db.new_app.description,
                                                            db.new_app.id_rand,
                                                            db.new_app.autor,
                                                            db.new_app.checked,
                                                            db.new_app.vhost_id,
                                                            db.new_app.plbsid_id,
                                                            db.new_app.max_fails,
                                                            db.new_app.fail_timeout,
                                                            db.new_app.Name,
                                                            db.new_app.backend_ip
                                                            )
        AppName = query[0]['app_name']

        if query[0]['checked'] == 1 :

            #query[0]['nginx_conf_data'] = query[0]['nginx_conf_data'].replace('#ssl_certificate', 'ssl_certificate')
            query[0]['modsec_conf_data'] = query[0]['modsec_conf_data'].replace('#SecAuditLog /opt/waf/nginx/var/log/'+ str(query[0]['app_name']) +'/audit_logs/'+ str(query[0]['vhost_id'])+'_'+ str(query[0]['app_name'])+ '_audit.log', 'SecAuditLog /opt/waf/nginx/var/log/'+ query[0]['app_name'] + '/audit_logs/'+ str(query[0]['vhost_id'])+'_'+ query[0]['app_name']+ '_audit.log')

            #Create Nginx default conf for new App
            CreateNginx = stuffs.CreateFiles()
            response = CreateNginx.CreateNginxFiles(ProdNginxAvail, AppName, query[0]['nginx_conf_data'])

            # Create Nginx symlink
            #CreateNginxLink = stuffs.CreateFiles()
            #response = CreateNginxLink.CreateNginxSymlink(ProdNginxAvail, AppName, 'prod')

            #Create folders and rules for new app
            CreateModsec = stuffs.CreateFiles()
            response = CreateModsec.CreateModsecFiles(ProdModsecRules, AppName, ProdModsecConf, query[0]['modsec_conf_data'].replace('tmp/',''))

            # Create symlinks from base_rules to enabled rules
            CreateLinks = stuffs.CreateFiles()
            response = CreateLinks.CreateSymlinksRules(ProdModsecRules, AppName)

            #create backend to prod path
            #subprocess.Popen(['mv', BackendTmp + AppName + '.conf', BackendProd],
            #                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #create listen folder
            subprocess.Popen(['mkdir', ListenPATH+'%s' %(AppName)])

            #Create log roation configuration
            log_rotation = stuffs.Maintenance()
            log_rotation.LogRotationFile(AppName)

            #create logs folder
            subprocess.Popen(['mkdir', '-p', '/opt/waf/nginx/var/log/%s/audit_logs/%s' %(AppName, AppName)])

            #create deny paths and headers directory
            subprocess.Popen(['mkdir', '-p', '/opt/waf/nginx/etc/rewrite/paths/%s' % (AppName)])

            #Remove temporal files
            subprocess.Popen(['rm', '-r', TmpNginxAvailable + '%s_nginx.conf' %(AppName)])

            subprocess.Popen(['rm', '-r', TmpNginxEnabled + '%s_nginx.conf' %(AppName)])

            subprocess.Popen(['rm', '-r', TmpListenPATH + '%s' %(AppName)])

            subprocess.Popen(['rm', '-r', BackendTmp + '%s.conf' %(AppName)])

            subprocess.Popen(['rm', '-r', TmpModsecRules + '%s' %(AppName)])

            subprocess.Popen(['rm', '-r', TmpModsecConf + '%s_modsec.conf' %(AppName)])


            db.production.insert(app_name=query[0]['app_name'],
                                 nginx_conf_data=query[0]['nginx_conf_data'],
                                 modsec_conf_data=query[0]['modsec_conf_data'].replace('tmp/','').replace("#grabthis", 'tmp'),
                                 description=query[0]['description'],
                                 id_rand=query[0]['id_rand'],
                                 autor=query[0]['autor'],
                                 vhost_id=query[0]['vhost_id'],
                                 plbsid_id=query[0]['plbsid_id'],
                                 max_fails=query[0]['max_fails'],
                                 fail_timeout=query[0]['fail_timeout'],
                                 backend_ip=query[0]['backend_ip'],
                                 Name=query[0]['Name'],
                                 enabled='Disabled',


                                 )
            db(db.new_app.id_rand == request.args[0]).delete()
            db2.defend_log_summary.insert(id_rand=request.args[0],
                                                  app_name=query[0]['app_name'],
                                                  critical=0,
                                                  warning=0,
                                                  alert=0,
                                                  notice=0,
                                                  error=0,
                                                  requests=0)
            NewLogApp(db2, auth.user.username, "Deploy: new deploy: " + query[0]['app_name'] )
            session.disabled = 'active'
            session.d_expanded = 'true'
            session.enabled = ''
            session.e_expanded = 'false'

            redirect(URL('Websites'))
        else:
            NewLogError(db2, auth.user.username, "Deploy: You must check the syntax before deploy!")
            session.flash = 'You must check the syntax before deploy!'
            redirect(URL('new_app'))


    else:
        redirect(URL('new_app'))

    return dict()


@auth.requires_login()
def DeleteNewApp():
    import os

    a = stuffs.Filtro()
    b = a.CheckStr(request.args[0])
    if b == 'YES':

        #Get App Name
        query = db(db.new_app.id_rand == request.args[0]).select(db.new_app.app_name)
        AppName =  str(query[0]['app_name'])



        #Delete configs files
        try:
            # Remove symbolic links in /opt/waf/nginx/etc/sites-enabled/
            subprocess.Popen(['rm', TmpNginxEnabled + query[0]['app_name'] + '_nginx.conf'],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Remove sites in /opt/waf/nginx/etc/sites-available/
            subprocess.Popen(['rm', TmpNginxAvailable + query[0]['app_name'] + '_nginx.conf'],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Remove modsecurity conf in /opt/waf/nginx/etc/modsecurity_conf/
            subprocess.Popen(['rm',  TmpModsecConf + query[0]['app_name'] + '_modsec.conf'],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # Remove modsecurity conf in /opt/waf/nginx/etc/modsec_rules/ **not working****
            subprocess.Popen(['rm', '-r ', TmpModsecRules + query[0]['app_name']],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            #this work
            os.system('rm -r %s%s' %(TmpModsecRules, query[0]['app_name']))

            #Remove Backend file
            subprocess.Popen(['rm', BackendTmp + query[0]['app_name']],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            #To avoid errors with configuration the logs folder in /opt/waf/nginx/var/log/app_log_folder is created when the app created and not when is deployed,
            #so to delete this log_folder firs we check if this app is in producion, if not we proceed todelete the folder
            is_in_prod = db(db.production.id_rand == request.args[0]).select(db.production.app_name)
            if is_in_prod:
                pass
            else:
                out = subprocess.Popen(['rm', '-r', LogsPATH + query[0]['app_name']],
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)


            db(db.new_app.id_rand == request.args[0]).delete()
            NewLogApp(db2, auth.user.username, "Deleted App: Deleted " + AppName)
            session.flash = 'App Deleted'

            session.enabled = ''
            session.disabled = 'active'


        except Exception as e:
            NewLogError(db2, auth.user.username, "Deleted app: " + str(e))
            session.flash = 'Error: ' + str(e)


    else:
    # Do nothing
        pass

    return redirect(URL('new_app'))


@auth.requires_login()
def new_app():


    query = db(db.new_app).select(db.new_app.app_name, db.new_app.autor, db.new_app.Name, db.new_app.id_rand, db.new_app.checked)


    return dict(query=query, page="Add a new application", icon="fa fa-plus", title="Create a new application")


@auth.requires_login()
def status():
    listening = subprocess.Popen(['sudo','netstat', '-tulpen'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out1,err1 = listening.communicate()
    p1 = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p2 = subprocess.Popen(['grep', 'nginx'], stdin=p1.stdout, stdout=subprocess.PIPE)
    running = p2.communicate()[0]

    if 'nginx' in out1:
        status = "Running and Listening"

    elif 'nginx: master' in running:
        status = "Running but not Listening"
    else:
        status = "Not Running\n"+str(err1)
    return status

@auth.requires_login()
def EngxEdit():

    #hacer filtro en caso de que vengan los datos en blanco (si se llama la funcion directamente arrojará error)
    a = stuffs.Filtro()
    b = a.CheckStr(request.args[0])

    if b == 'YES':
        """
        if request.args[1] == 'tmp':

            try:

                db(db.new_app.id_rand == request.args[0]).update(nginx_conf_data = request.vars.keys()[0])
                query = db(db.new_app.id_rand == request.args[0]).select(db.new_app.nginx_conf_data, db.new_app.app_name)
                DataNginx = query[0]['nginx_conf_data']
                AppName = query[0]['app_name']
                UpdateFiles = stuffs.CreateFiles()
                UpdateFiles.CreateNginxFiles(TmpNginxAvailable, AppName, DataNginx)
                response.flash = 'Configuracion Guardada'
                NewLogApp(db2, auth.user.username, "EngxEdit: tmp saved configuration app: " + AppName)

            except Exception as e:
                NewLogError(db2, auth.user.username, "EngxEdit: " + str(e))
                response.flash = e
        """
        if request.args[1] == 'prod':
            try:

                db(db.production.id_rand == request.args[0]).update(nginx_conf_data=request.vars.keys()[0])
                query = db(db.production.id_rand == request.args[0]).select(db.production.nginx_conf_data, db.production.app_name)
                DataNginx = query[0]['nginx_conf_data']
                AppName = query[0]['app_name']
                UpdateFiles = stuffs.CreateFiles()
                UpdateFiles.CreateNginxFiles(ProdNginxAvail, AppName, DataNginx)
                #UpdateFiles.CreateNginxSymlink(ProdNginxAvail, AppName, 'prod')
                response.flash = 'Configuration Saved'
                r = stuffs.Nginx()
                r.Reload()
                NewLogApp(db2, auth.user.username, "EngxEdit: prod saved configuration app: " + AppName)
            except Exception as e:
                NewLogError(db2, auth.user.username, "EngxEdit: " + str(e))
                response.flash = e

        else:
            response.flash = "Error in data supplied"
            redirect(URL('new_app'))

    else:
        redirect(URL('new_app'))


@auth.requires_login()
def ModsEdit():

    # hacer filtro en caso de que vengan los datos en blanco (si se llama la funcion directamente arrojará error)
    a = stuffs.Filtro()
    b = a.CheckStr(request.args[0])

    if b == 'YES':
        if request.args[1] == 'tmp':
            """
            try:

                db(db.new_app.id_rand == request.args[0]).update(modsec_conf_data=request.vars.keys()[0])
                query = db(db.new_app.id_rand == request.args[0]).select(db.new_app.modsec_conf_data, db.new_app.app_name)
                DataModsec = query[0]['modsec_conf_data']
                AppName = query[0]['app_name']

                UpdateFiles = stuffs.CreateFiles()
                UpdateFiles.CreateModsecConf('tmp', AppName, DataModsec)
                response.flash = 'Configuracion Guardada'
                NewLogApp(db2, auth.user.username, "ModsEdit: tmp saved configuration app: " + AppName)

            except Exception as e:
                response.flash = e
                NewErrorApp(db2, auth.user.username, "ModsEdit: tmp " + str(e))
        """
        if request.args[1] == 'prod':
            try:

                db(db.production.id_rand == request.args[0]).update(modsec_conf_data=request.vars.keys()[0])
                query = db(db.production.id_rand == request.args[0]).select(db.production.modsec_conf_data, db.production.app_name)
                DataModsec = query[0]['modsec_conf_data']
                AppName = query[0]['app_name']

                UpdateFiles = stuffs.CreateFiles()
                UpdateFiles.CreateModsecConf('prod', AppName, DataModsec)
                response.flash = 'Configuration Saved'
                a = stuffs.Nginx()
                b = a.Reload()
                NewLogApp(db2, auth.user.username, "ModsEdit: prod saved configuration app: " + AppName)


            except Exception as e:
                response.flash = e
                NewErrorApp(db2, auth.user.username, "ModsEdit: prod " + str(e))
        else:
            response.flash = "Error in data supplied"

    else:
        response.flash = "Error in data supplied"
        redirect(URL('new_app'))

""""@auth.requires_login()
def SvAppName():
    try:
        # Check if AppName contains dangereus characters
        if any(c in request.args[0] for c in "\"/'\;,=%#$*()[]?¿¡{}:!|&<>¨~°^ "):
            session.flash = 'Invalid characters found'
            NewLogError(db2, auth.user.username, "SvAppName: Invalid characters found")
            redirect(URL('new_app'))


        else:
            db(db.new_app.id_rand == request.args[0]).update(app_name=request.vars.keys()[0])
            NewLogApp(db2, auth.user.username, "SvAppName: updated " + request.vars.keys()[0])

    except Exception as e:
        NewLogError(db2, auth.user.username, "SvAppName: " + str(e))
        redirect(URL('new_app'))
"""


@auth.requires_login()
def BackendIps():
    import urllib, os


    f = stuffs.Filtro()
    b = f.CheckStr(request.vars['id'])
    if b == 'YES':
        IPS_http = urllib.unquote(urllib.unquote(request.vars['http']))
        IPS_https = urllib.unquote(urllib.unquote(request.vars['https']))
        create_backend = stuffs.CreateFiles()
        #print 'https: ', IPS_https
        #print 'http: ', IPS_http
        try:
            """
            if request.vars['env'] == 'tmp':
                query = db(db.new_app.id_rand == request.vars['id']).select(db.new_app.app_name, db.new_app.max_fails,
                                                                        db.new_app.fail_timeout, db.new_app.vhost_id,
                                                                        db.new_app.plbsid_id)
                db(db.new_app.id_rand == request.vars['id']).update(backend_ip=ips)
                "\"/'\;,=%#$*()[]?¿¡!{}:|&<>¨~°^ ")
            """
            check_list = []
            if any(c in IPS_http for c in "\"';,%#$*=()[]{}?¿¡!|&<>¨~°-^ "):
                check_list.append('NO')
            if any(c in IPS_https for c in "\"';,%#$*=()[]{}?¿¡!|&<>¨~°-^ "):
                check_list.append('NO')
            else:
                check_list.append('YES')
            print check_list
            if request.vars['env'] == 'prod' and 'NO' not in check_list:
                query = db(db.production.id_rand == request.vars['id']).select(db.production.app_name, db.production.max_fails,
                                                                        db.production.fail_timeout, db.production.vhost_id,
                                                                        db.production.plbsid_id)
                db(db.production.id_rand == request.vars['id']).update(backend_ip_http="\n".join(IPS_http.splitlines()))
                db(db.production.id_rand == request.vars['id']).update(backend_ip_https="\n".join(IPS_https.splitlines()))

                os.system('echo "" > /opt/waf/nginx/etc/backend/%s.conf ' % (query[0]['app_name']))

                # create http backend
                if IPS_http != '':
                    r = create_backend.CreateBackend(request.vars['env'], str(query[0]['app_name']), IPS_http.splitlines(),
                                                     str(query[0]['vhost_id']), query[0]['max_fails'],
                                                     query[0]['fail_timeout'], query[0]['plbsid_id'], 'http')

                # create https backend
                if IPS_https != '':
                    r = create_backend.CreateBackend(request.vars['env'], str(query[0]['app_name']), IPS_https.splitlines(),
                                                     str(query[0]['vhost_id']), query[0]['max_fails'],
                                                     query[0]['fail_timeout'], query[0]['plbsid_id'], 'https')
                NewLogApp(db2, auth.user.username, "BackendIps: backend saved app " + str(query[0]['app_name']))
                response.flash = r

            else:
                response.flash = "Error in backend supplied"

        except Exception as e:
            NewLogError(db2, auth.user.username, "BackendIps: " + str(e))
            response.flash = e
    else:
        response.flash = "Error in data supplied"

    #print request.args

    return dict()


@auth.requires_login()
def CheckProd():

    s = stuffs.Nginx()
    r = s.SyntaxCheck()
    if "Syntax OK" in r:
        session.flash = 'Syntax OK'
        redirect(URL('Websites'))
    else:
        redirect(URL('Websites'))
    return dict()

@auth.requires_login()
def EnableApp():

    c = stuffs.Filtro()
    d = c.CheckStr(request.args[0])
    if d == 'YES':


        query = db(db.production.id_rand == request.args[0]).select(db.production.app_name, db.production.listen_ip)
        AppName = str(query[0]['app_name'])

        if query[0]['listen_ip'] != None:

            # Reload Nginx
            a = stuffs.Nginx()
            b = a.Reload()

            if 'Bad Syntax' in b:
                session.flash = 'Error in configuration, Not Enabled. --> ' + b
                NewLogError(db2, auth.user.username, "EnableApp: Error in configuration, Not Enabled. --> " + str(b))
                redirect(URL('Websites'))
            else:
                #Enable app
                subprocess.Popen(['ln', '-sf', ProdNginxAvail + AppName + '_nginx.conf',
                             ProdNginxEnabled], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                db(db.production.id_rand == request.args[0]).update(enabled='Enabled')
                #change ownership to audit logs, otherwise they will not appear in the view
                subprocess.Popen(['chown', '-R', 'www-data.www-data','/opt/waf/nginx/var/log/audit_logs/%s' %(AppName)])
                NewLogApp(db2, auth.user.username, "EnableApp: Enabled " + AppName)
                session.flash = AppName + ' Enabled'
                a.Reload()
                redirect(URL('Websites'))
                session.enabled = 'active'
                session.e_expanded = 'true'
                session.d_expanded = 'false'
                session.disabled = ''

                subprocess.Popen(['sudo', 'chown', '-R', 'www-data.www-data', '/opt/waf/nginx/var/log/'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.Popen(['sudo', 'chmod', '755', '-R', '/opt/waf/nginx/var/log/'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        else:
            session.flash = AppName + " has no IP assigned, first assign an IP to listen"
            redirect(URL('Websites'))
    else:
        redirect(URL('Websites'))

    return dict(active='active')

@auth.requires_login()
def DisableApp():

    a = stuffs.Filtro()
    b = a.CheckStr(request.args[0])
    if b == 'YES':


        query = db(db.production.id_rand == request.args[0]).select(db.production.app_name)

        # Remove symbolic links in /opt/waf/nginx/etc/sites-enabled/
        subprocess.Popen(['rm', ProdNginxEnabled + query[0]['app_name'] + '_nginx.conf'],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        db(db.production.id_rand == request.args[0]).update(enabled='Disabled')

        # Reload Nginx
        a = stuffs.Nginx()
        b = a.Reload()

        if 'Bad Syntax' in b:
            session.flash = B(SPAN('Disabled but I will not reload until you fix the error: ->  ')) + b
            NewLogError(db2, auth.user.username, "DisableApp: Disabled but I will not reload until you fix the error: ->   " + str(b))
            redirect(URL('Websites'))
        else:
            NewLogApp(db2, auth.user.username, 'DisableApp: ' + query[0]['app_name'] + ' Disabled' )
            session.flash = query[0]['app_name'] + ' Disabled'
            redirect(URL('Websites'))
            session.enabled = ''
            session.e_expanded = 'false'
            session.d_expanded = 'true'
            session.disabled = 'active'

    else:
        redirect(URL('Websites'))
    return dict()

@auth.requires_login()
def XssFilter():

    try:
        c = stuffs.Filtro()
        d = c.CheckStr(request.vars['id'])
        if d == 'YES':
            query = db(db.production.id_rand == request.vars['id']).select(db.production.app_name)
            AppName = str(query[0]['app_name'])

            if request.vars['env'] == 'prod' and request.vars['status'] == 'On':
                #create symbolic link to xss rule
                subprocess.Popen(['ln', '-sf', ProdModsecRules + AppName + '/base_rules/' + Xss,
                                  ProdModsecRules + AppName + '/enabled_rules/'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
                # Reload Nginx
                a = stuffs.Nginx()
                a.Reload()
                db(db.production.id_rand == request.vars['id']).update(xss_filter = 'ON')
                response.flash = "XSS Protection Enabled"
                message = 'Enabled'
                NewLogApp(db2, auth.user.username, "XssFilter: " + AppName + "XSS Protection Enabled")

            elif request.vars['env'] == 'prod' and request.vars['status'] == 'Off':
                # remove symbolic link to xss rule
                subprocess.Popen(['rm', ProdModsecRules + AppName + '/enabled_rules/' + Xss], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

                # Reload Nginx
                a = stuffs.Nginx()
                a.Reload()
                db(db.production.id_rand == request.vars['id']).update(xss_filter = 'OFF')
                response.flash = "XSS Protection Disabled"
                message = 'Disabled'
                NewLogApp(db2, auth.user.username, "XssFilter: " + AppName + "XSS Protection Enabled")

    except Exception as e:
        message = 'Error: ' + str(e)
        NewLogError(db2, auth.user.username, "XssFilter: " + str(e ) )

    return message

@auth.requires_login()
def SqliFilter():

    try:
        c = stuffs.Filtro()
        d = c.CheckStr(request.vars['id'])
        if d == 'YES':
            query = db(db.production.id_rand == request.vars['id']).select(db.production.app_name)
            AppName = str(query[0]['app_name'])

            if request.vars['env'] == 'prod' and request.vars['status'] == 'On':
                #create symbolic link to xss rule
                subprocess.Popen(['ln', '-sf', ProdModsecRules + AppName + '/base_rules/' + Sqli,
                                  ProdModsecRules + AppName + '/enabled_rules/'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

                # Reload Nginx
                a = stuffs.Nginx()
                a.Reload()
                db(db.production.id_rand == request.vars['id']).update(sqli_filter = 'ON')
                response.flash = "SQL Injection Protection Enabled"
                message = 'Enabled'
                NewLogApp(db2, auth.user.username, "SqliFilter: " + AppName + " : SQL Injection Protection Enabled")

            elif request.vars['env'] == 'prod' and request.vars['status'] == 'Off':
                # remove symbolic link to xss rule
                subprocess.Popen(['rm', ProdModsecRules + AppName + '/enabled_rules/' + Sqli], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

                # Reload Nginx
                a = stuffs.Nginx()
                a.Reload()
                db(db.production.id_rand == request.vars['id']).update(sqli_filter = 'OFF')
                response.flash = "SQL Injection Protection Disabled"
                message = 'Disabled'
                NewLogApp(db2, auth.user.username, "SqliFilter: " + AppName + " : SQL Injection Protection Disabled")

    except Exception as e:
        message = 'Error: ' + str(e)
        NewLogError(db2, auth.user.username, "SqliFilter: " + str(e))

    return message


@auth.requires_login()
def ProtoAnomaliesFilter():

    try:
        c = stuffs.Filtro()
        d = c.CheckStr(request.vars['id'])
        if d == 'YES':
            query = db(db.production.id_rand == request.vars['id']).select(db.production.app_name)
            AppName = str(query[0]['app_name'])

            if request.vars['env'] == 'prod' and request.vars['status'] == 'On':
                #create symbolic link to xss rule
                subprocess.Popen(['ln', '-sf', ProdModsecRules + AppName + '/base_rules/' + ProtoAnomalies,
                                  ProdModsecRules + AppName + '/enabled_rules/'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
                # Reload Nginx
                a = stuffs.Nginx()
                a.Reload()
                db(db.production.id_rand == request.vars['id']).update(proto_anomalies_filter = 'ON')
                response.flash = "Proto Anomalies Protection Enabled"
                message = 'Enabled'
                NewLogApp(db2, auth.user.username, "ProtoAnomaliesFilter: " + AppName + " : Proto Anomalies Protection Enabled")

            elif request.vars['env'] == 'prod' and request.vars['status'] == 'Off':
                # remove symbolic link to xss rule
                subprocess.Popen(['rm', ProdModsecRules + AppName + '/enabled_rules/' + ProtoAnomalies], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

                # Reload Nginx
                a = stuffs.Nginx()
                a.Reload()
                db(db.production.id_rand == request.vars['id']).update(proto_anomalies_filter = 'OFF')
                response.flash = "Proto Anomalies Protection Disabled"
                message = 'Disabled'
                NewLogApp(db2, auth.user.username, "ProtoAnomaliesFilter: " + AppName + " : Proto Anomalies Protection Disabled")

    except Exception as e:
        message = 'Error: ' + str(e)
        NewLogError(db2, auth.user.username, "ProtoAnomaliesFilter")

    return message

@auth.requires_login()
def ProtoViolationsFilter():

    try:
        c = stuffs.Filtro()
        d = c.CheckStr(request.vars['id'])
        if d == 'YES':
            query = db(db.production.id_rand == request.vars['id']).select(db.production.app_name)
            AppName = str(query[0]['app_name'])

            if request.vars['env'] == 'prod' and request.vars['status'] == 'On':
                #create symbolic link to xss rule
                subprocess.Popen(['ln', '-sf', ProdModsecRules + AppName + '/base_rules/' + ProtoViolations,
                                  ProdModsecRules + AppName + '/enabled_rules/'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
                # Reload Nginx
                a = stuffs.Nginx()
                a.Reload()
                db(db.production.id_rand == request.vars['id']).update(proto_violations_filter = 'ON')
                response.flash = "Proto Violations Protection Enabled"
                message = 'Enabled'
                NewLogApp(db2, auth.user.username, "ProtoViolationsFilter: " + AppName + " Proto Violations Protection Enabled" )

            elif request.vars['env'] == 'prod' and request.vars['status'] == 'Off':
                # remove symbolic link to xss rule
                subprocess.Popen(['rm', ProdModsecRules + AppName + '/enabled_rules/' + ProtoViolations], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

                # Reload Nginx
                a = stuffs.Nginx()
                a.Reload()
                db(db.production.id_rand == request.vars['id']).update(proto_violations_filter = 'OFF')
                response.flash = "Proto Violations Protection Disabled"
                message = 'Disabled'
                NewLogApp(db2, auth.user.username, "ProtoViolationsFilter: " + AppName + " Proto Violations Protection Disabled" )

    except Exception as e:
        message = 'Error: ' + str(e)
        NewLogError(db2, auth.user.username, "ProtoViolationsFilter: " + str(e))

    return message

@auth.requires_login()
def GenericFilter():

    try:
        c = stuffs.Filtro()
        d = c.CheckStr(request.vars['id'])
        if d == 'YES':
            query = db(db.production.id_rand == request.vars['id']).select(db.production.app_name)
            AppName = str(query[0]['app_name'])

            if request.vars['env'] == 'prod' and request.vars['status'] == 'On':
                #create symbolic link to xss rule
                subprocess.Popen(['ln', '-sf', ProdModsecRules + AppName + '/base_rules/' + Generic,
                                  ProdModsecRules + AppName + '/enabled_rules/'], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
                # Reload Nginx
                a = stuffs.Nginx()
                a.Reload()
                db(db.production.id_rand == request.vars['id']).update(generic_filter = 'ON')
                response.flash = "Generic Attacks Protection Enabled"
                message = 'Enabled'
                NewLogApp(db2, auth.user.username, "GenericFilter: " + AppName + " Generic Attacks Protection Enabled")

            elif request.vars['env'] == 'prod' and request.vars['status'] == 'Off':
                # remove symbolic link to xss rule
                subprocess.Popen(['rm', ProdModsecRules + AppName + '/enabled_rules/' + Generic], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

                # Reload Nginx
                a = stuffs.Nginx()
                a.Reload()
                db(db.production.id_rand == request.vars['id']).update(generic_filter = 'OFF')
                response.flash = "Generic Attacks Protection Disabled"
                message = 'Disabled'
                NewLogApp(db2, auth.user.username, "GenericFilter: " + AppName + " :Generic Attacks Protection Disabled")

    except Exception as e:
        message = 'Error: ' + str(e)
        NewLogError(db2, auth.user.username, "GenericFilter: " + str(e))
    return message


@auth.requires_login()
def Listen():
    import stuffs
    import os
    import changeconfig

    a = stuffs.Filtro()
    b = a.CheckStr(request.vars['id'])
    c = a.CheckStrIP(request.vars['listen_ip'])
    d = a.CheckPorts(request.vars['http_ports'])
    e = a.CheckPorts(request.vars['https_ports'])
    #Get a list with the ips saved in "Add Interface" function
    ips = db(db.system).select(db.system.iface_ip)
    #Get actual ip
    actual_ip = db(db.production.id_rand == request.vars['id']).select(db.production.listen_ip)
    query = db(db.production.id_rand == request.vars['id']).select(db.production.nginx_conf_data, db.production.app_name)
    #if id and listen_ip and ports are valid
    if b == 'YES' and c == 'YES' and (d == 'YES' or e == 'YES') == True:
        #asign ports to variables
        http = request.vars['http_ports']
        https = request.vars['https_ports']
        #if multiples come they will be separated in a new line
        if '-' in request.vars['http_ports']:
            request.vars['http_ports'] = request.vars['http_ports'].replace('-','\n')
        if '-' in request.vars['https_ports']:
            request.vars['https_ports'] = request.vars['https_ports'].replace('-','\n')
        try:
            for i in ips:
                #print 'for i in ips:', i
                # if is in the list we do all :-)
                if request.vars['listen_ip'] in i['iface_ip']:
                    #remove listen files
                    os.system('rm %s%s/listenHTTP.conf' %(ListenPATH, query[0]['app_name']))
                    os.system('rm %s%s/listenHTTPS.conf' %(ListenPATH, query[0]['app_name']))


                    #check if new ip is the same than the actual ip
                    if actual_ip[0]['listen_ip'] == request.vars['listen_ip']:
                        pass


                    #if is different
                    if actual_ip[0]['listen_ip'] != request.vars['listen_ip']:
                        #check if other app is using this ip and get the app_name
                        is_used_by = db(db.system.iface_ip == actual_ip[0]['listen_ip']).select(db.system.used_by)
                        if is_used_by:
                            is_used_by = is_used_by[0]['used_by'].replace(", "+query[0]['app_name'],"")
                            is_used_by = is_used_by.replace(query[0]['app_name']+", ","")
                            is_used_by = is_used_by.replace(query[0]['app_name'],"")
                            #update list of apps using this ip
                            if is_used_by == "":
                                is_used_by = None
                                db(db.system.iface_ip == actual_ip[0]['listen_ip']).update(used_by=is_used_by, available='Available')
                            else:
                                db(db.system.iface_ip == actual_ip[0]['listen_ip']).update(used_by=is_used_by)
                        else:
                            is_used_by = None
                            db(db.system.iface_ip == actual_ip[0]['listen_ip']).update(used_by=is_used_by, available='Available')

                        #check if new ip has other apps
                        new_ip_used_by = db(db.system.iface_ip == request.vars['listen_ip']).select(db.system.used_by)
                        #print "new_ip_used_by: ", new_ip_used_by[0]
                        if new_ip_used_by[0]['used_by'] != None:
                            new_ip_used_by = new_ip_used_by[0]['used_by']+", "+query[0]['app_name']
                            #update list of apps using this ip
                            db(db.system.iface_ip == request.vars['listen_ip']).update(used_by=new_ip_used_by, available='In use')

                        else:
                            #print 'Else'
                            db(db.system.iface_ip == request.vars['listen_ip']).update(used_by=query[0]['app_name'], available='In use')

                        #Update production ip with the new ip
                        db(db.production.id_rand == request.vars['id']).update(listen_ip=request.vars['listen_ip'])
                        response.flash = 'Configuration Saved'

                    #get nginx conf data
                    DataNginx = query[0]['nginx_conf_data']
                    #If http ports are selected and valid, it will be created the listen file config
                    if d == 'YES' and e == 'NO':
                        #update http ports
                        db(db.production.id_rand == request.vars['id']).update(ports_http=http)
                        db(db.production.id_rand == request.vars['id']).update(ports_https='')
                        f = open('%s%s/listenHTTP.conf' %(ListenPATH, query[0]['app_name']), 'a')
                        for port in request.vars['http_ports'].splitlines():
                            #print "Adding configuration"
                            f.write('listen %s:%s;' %(request.vars['listen_ip'], port))
                            f.write('\n')
                        f.close()
                        #Descomment SSL
                        if "#ssl_certificate" is not query[0]['nginx_conf_data']:
                            query[0]['nginx_conf_data'] = query[0]['nginx_conf_data'].replace('ssl_certificate', '#ssl_certificate')
                        DataNginx = query[0]['nginx_conf_data']
                        AppName = query[0]['app_name']
                        UpdateFiles = stuffs.CreateFiles()
                        UpdateFiles.CreateNginxFiles(ProdNginxAvail, AppName, DataNginx)
                        u = stuffs.Nginx()
                        u.Reload()
                        db(db.production.id_rand == request.vars['id']).update(nginx_conf_data=query[0]['nginx_conf_data'])
                        session.flash = 'Configuration Saved'

                        #print 'Listen http writed'
                    #If https ports are selected and valid, it will be created the listen file config
                    if e == 'YES' and d == 'NO':
                        #update https ports
                        db(db.production.id_rand == request.vars['id']).update(ports_https=https)
                        db(db.production.id_rand == request.vars['id']).update(ports_http='')
                        f = open('%s%s/listenHTTPS.conf' %(ListenPATH, query[0]['app_name']), 'a')
                        for port in request.vars['https_ports'].splitlines():
                            #print "Adding configuration"
                            f.write('listen %s:%s ssl;' %(request.vars['listen_ip'], port))
                            f.write('\n')
                        f.close()
                        #print 'Listen https writed'
                        #Create dir ssl
                        process = subprocess.Popen(['mkdir', SslPATH + query[0]['app_name']], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                        query[0]['nginx_conf_data'] = query[0]['nginx_conf_data'].replace('#ssl_certificate', 'ssl_certificate')
                        DataNginx = query[0]['nginx_conf_data']
                        AppName = query[0]['app_name']
                        UpdateFiles = stuffs.CreateFiles()
                        UpdateFiles.CreateNginxFiles(ProdNginxAvail, AppName, DataNginx)
                        u = stuffs.Nginx()
                        u.Reload()
                        db(db.production.id_rand == request.vars['id']).update(nginx_conf_data=query[0]['nginx_conf_data'])
                        response.flash = 'Configuration Saved'


                    if e == 'YES' and d == 'YES':
                        #update https ports
                        db(db.production.id_rand == request.vars['id']).update(ports_https=https)
                        db(db.production.id_rand == request.vars['id']).update(ports_http=http)
                        #Https part
                        f = open('%s%s/listenHTTPS.conf' %(ListenPATH, query[0]['app_name']), 'a')
                        for port in request.vars['https_ports'].splitlines():
                            #print "Adding configuration"
                            f.write('listen %s:%s ssl;' %(request.vars['listen_ip'], port))
                            f.write('\n')
                        f.close()
                        #HTTP part
                        f = open('%s%s/listenHTTP.conf' %(ListenPATH, query[0]['app_name']), 'a')
                        for port in request.vars['http_ports'].splitlines():
                            #print "Adding configuration"
                            f.write('listen %s:%s;' %(request.vars['listen_ip'], port))
                            f.write('\n')
                        f.close()
                        process = subprocess.Popen(['mkdir', SslPATH + query[0]['app_name']], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        process, err = process.communicate()

                        query[0]['nginx_conf_data'] = query[0]['nginx_conf_data'].replace('#ssl_certificate', 'ssl_certificate')
                        DataNginx = query[0]['nginx_conf_data']
                        AppName = query[0]['app_name']
                        UpdateFiles = stuffs.CreateFiles()
                        UpdateFiles.CreateNginxFiles(ProdNginxAvail, AppName, DataNginx)
                        u = stuffs.Nginx()
                        u.Reload()
                        db(db.production.id_rand == request.vars['id']).update(nginx_conf_data=query[0]['nginx_conf_data'])

                        NewLogApp(db2, auth.user.username, "Listen: " + query[0]['app_name'] + " -> " + request.vars['listen_ip'] )
                        #reload changes
                        a = stuffs.Nginx()
                        a.Reload()
                        response.flash = 'Configuration Saved'

                    break

                else:
                    # if no in list we do nothing >:(
                    pass
                    #response.flash = 'Invalid Ip'
        except Exception as e:
            #NewLogError(db2, auth.user.username, "Listen: " + query[0]['app_name'] )
            response.flash = str(e)
            #print 'Error:', e
    else:
        response.flash = 'Error in data supplied'
    return dict()

@auth.requires_login()
def Mode():
    a = stuffs.Filtro()
    id_rand = a.CheckStr(request.vars['id'])
    alias_mode = request.vars['mode']
    modes = ['Bridge', 'Vigilant', 'Defend']
    modsec_list = []
    if id_rand == 'YES' and alias_mode in modes:
        
        if alias_mode == 'Bridge':
            mode = 'Off'
        elif alias_mode == 'Vigilant':
            mode = 'DetectionOnly'
        elif alias_mode == 'Defend':
            mode = 'On'
        else:
            mode = 'On'
            alias_mode = 'Defend'
            
        modsec = db(db.production.id_rand == request.vars['id']).select(db.production.modsec_conf_data, db.production.app_name,db.production.mode)
        modsec_data = modsec[0]['modsec_conf_data']
        #change configuration
        #Change return a dictionary with status message and the new list whith changed configuration ex: {'newconf_list': 'data', 'message':'success or error'}
        change = changeconfig.Change()
        r = change.Text(modsec_data, 'SecRuleEngine', "SecRuleEngine %s" %(mode))
        db(db.production.id_rand == request.vars['id']).update(modsec_conf_data='\n'.join(r['new_list']), mode=alias_mode)


        #get new conf
        new = db(db.production.id_rand == request.vars['id']).select(db.production.modsec_conf_data)

        UpdateFiles = stuffs.CreateFiles()
        try:
            UpdateFiles.CreateModsecConf('prod', modsec[0]['app_name'], new[0]['modsec_conf_data'])
            NewLogApp(db2, auth.user.username, "Mode: prod " +  modsec[0]['app_name'])
        except Exception as e:
            NewLogError(db2, auth.user.username, "Mode: " + str(e))
            session.flash = e
        #response.flash = 'Configuracion Guardada'
        a = stuffs.Nginx()
        b = a.Reload()

        msg = 'Mode %s enabled' %(request.vars['mode'])
        session.flash = 'Mode %s enabled' %(request.vars['mode'])
    else:
        msg = 'Error'
        NewLogError(db2, auth.user.username, "Mode: Error")


    return response.json(msg)
