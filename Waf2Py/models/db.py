# Chris - cvaras@itsec.cl
# -*- coding: utf-8 -*-

db = DAL ('sqlite://waf2py.sqlite',folder='/home/www-data/waf2py_community/applications/Waf2Py/databases')
db2 = DAL ('sqlite://waf_logs.sqlite',folder='/home/www-data/waf2py_community/applications/Waf2Py/databases')


# -------------------------------------------------------------------------
# app configuration made easy. Look inside private/appconfig.ini
# -------------------------------------------------------------------------
from gluon.contrib.appconfig import AppConfig
myconf = AppConfig(reload=False)

# choose a style for forms
# -------------------------------------------------------------------------
response.formstyle = myconf.get('forms.formstyle')  # or 'bootstrap3_stacked' or 'bootstrap2' or other
#response.formstyle = 'bootstrap3_stacked'
response.form_label_separator = myconf.get('forms.separator') or ''

db.define_table('examples',
                Field('conf_name', 'string', length=30,requires=IS_NOT_EMPTY()),
                Field('data_conf', 'text', requires=IS_NOT_EMPTY()),
                Field('description', 'text', requires=IS_NOT_EMPTY()),
                Field('autor', 'string', length=15,requires=IS_NOT_EMPTY()),
                )

db.define_table('basic_conf',
                Field('nginx_data_conf', 'text', requires=IS_NOT_EMPTY()),
                Field('modsec_data_conf', 'text'),
                Field('description', 'text', requires=IS_NOT_EMPTY()),
                Field('autor', 'string', length=15,requires=IS_NOT_EMPTY()),
                )

db.define_table('new_app',
                Field('app_name', 'string', length=100, requires=IS_NOT_EMPTY()),
                Field('nginx_conf_data', 'text', requires=IS_NOT_EMPTY()),
                Field('modsec_conf_data', 'text', requires=IS_NOT_EMPTY()),
                Field('autor', 'string', length=15,requires=IS_NOT_EMPTY()),
                Field('description', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('checked', 'integer', length=1, requires=IS_NOT_EMPTY()),
                Field('deployed', 'integer',  length=1,requires=IS_NOT_EMPTY()),
                Field('id_rand', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('Name', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('vhost_id', 'integer', length=4,requires=IS_NOT_EMPTY()),
                Field('plbsid_id', 'integer', length=4,requires=IS_NOT_EMPTY()),
                Field('fail_timeout', 'integer', length=3,default='60',requires=IS_NOT_EMPTY()),
                Field('max_fails', 'integer', length=2,default='1',requires=IS_NOT_EMPTY()),
                Field('backend_ip', 'string', requires=IS_NOT_EMPTY()),
                Field('listen_ip', 'string', length=45,requires=IS_NOT_EMPTY()),


                )

db.define_table('production',
                Field('app_name', 'string', length=100,requires=IS_NOT_EMPTY()),
                Field('nginx_conf_data', 'text', requires=IS_NOT_EMPTY()),
                Field('modsec_conf_data', 'text', requires=IS_NOT_EMPTY()),
                Field('autor', 'string', length=30,requires=IS_NOT_EMPTY()),
                Field('description', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('id_rand', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('enabled', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('listening', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('Name', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('vhost_id', 'integer', length=4,requires=IS_NOT_EMPTY()),
                Field('plbsid_id', 'integer', length=4,requires=IS_NOT_EMPTY()),
                Field('xss_filter', 'string', length=3,default='ON'),
                Field('sqli_filter', 'string', length=3,default='ON'),
                Field('proto_anomalies_filter', 'string', length=3,default='ON'),
                Field('proto_violations_filter', 'string', length=3, default='ON'),
                Field('generic_filter', 'string', length=3, default='ON'),
                Field('fail_timeout', 'integer', length=3,default='60'),
                Field('max_fails', 'integer', length=2,default='1'),
                #Field('backend_ip', 'string', requires=IS_NOT_EMPTY()),
                Field('listen_ip', 'string', length=45,requires=IS_NOT_EMPTY()),
                Field('mode', 'string', length=10, default="Defend", requires=IS_IN_SET(["Defend","Vigilant","Bridge"])),
                Field('ports_http', 'string', length=5,default="80"),
                Field('ports_https', 'string', length=5,default="443"),
                Field('extra_headers', 'string', default=""),
                Field('paths_denied', 'string', default=""),
                Field('backend_ip_http', 'string', default=""),
                Field('backend_ip_https', 'string', default=""),
                )

db.define_table('logs',
                Field('app_name', 'string'),
                Field('nginx_error', 'string'),
                Field('nginx_access', 'string'),
                Field('modsec_audit', 'string'),
                Field('application_logs', 'string'),
                Field('type_attack', 'string'),
                Field('uri', 'string'),
                Field('level', 'string'),
                Field('ip_attacker', 'string'),
                Field('ip_dst', 'string'),
                Field('date', 'string'),
                )


db.define_table('system',
                Field('iface_ip', 'string',requires=IS_NOT_EMPTY()),
                Field('iface_name', 'string', length=10,requires=IS_NOT_EMPTY()),
                Field('used_by', 'string', length=100,requires=IS_NOT_EMPTY()),
                Field('available', 'string', length=20,default="Available",requires=IS_NOT_EMPTY()),
                Field('number', 'integer', length=2,requires=IS_NOT_EMPTY()),

                )

db.define_table('certificate',
                Field('id_rand', 'string', length=50, requires=IS_NOT_EMPTY()),
                Field('cert', 'string'),
                Field('chain', 'string'),
                Field('privkey', 'string'),
                Field('protocol', 'list:string'),
                Field('prefer_cipher', 'string'),
                Field('ciphers', 'string'))

db2.define_table('log_app',
                Field('username'),
                Field('time'),
                Field('msg', 'text'))

db2.define_table('log_error',
                Field('username'),
                Field('time'),
                Field('msg', 'text'))

db.define_table('exclusions',
                Field('id_rand', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('rules_id', 'string', length=10, requires=IS_NOT_EMPTY()),
                Field('attack_name', 'string', length=30, requires=IS_NOT_EMPTY()),
                Field('type', 'integer', length=1, requires=IS_NOT_EMPTY()),
                Field('local_path', 'string', requires=IS_NOT_EMPTY()),
                Field('user', 'string'),
                Field('custom_id', 'integer', length=6,requires=IS_NOT_EMPTY())
                )

db.define_table('routes',
                Field('id_rand', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('ip', requires=IS_NOT_EMPTY()),
                Field('gw_ip', requires=IS_NOT_EMPTY()),
                Field('iface', requires=IS_NOT_EMPTY()))

db.define_table('logs_file',
                Field('id_rand', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('log_name', 'string', length=100,requires=IS_NOT_EMPTY()),
                Field('type', 'string', length=6,requires=IS_NOT_EMPTY()),
                Field('size', 'string', length=10,requires=IS_NOT_EMPTY()),
                Field('date', 'string', length=10,requires=IS_NOT_EMPTY()),
                Field('id_rand2', 'string', length=50,requires=IS_NOT_EMPTY()),
                )

db.define_table('n_interfaces',
                Field('number', 'integer', length=3,default=0),
                )

db2.define_table('defend_log_summary',
                Field('app_name', 'string'),
                Field('id_rand', 'string', length=50,requires=IS_NOT_EMPTY()),
                Field('critical', 'integer'),
                Field('warning', 'integer'),
                Field('alert', 'integer'),
                Field('notice', 'integer'),
                Field('error', 'integer'),
                Field('requests', 'integer'),

                )



from gluon.tools import Auth
from gluon.tools import Recaptcha2
auth = Auth(db)
auth.settings.captcha = Recaptcha2(request, public_key='xxxx', private_key='xxxx')
auth.define_tables(username=True,signature=True,)
#auth.settings.login_next=URL('Websites')
auth.settings.logout_next=URL()

#Comment the following line to allow registration
auth.settings.actions_disabled.append('register')

auth.settings.everybody_group_id = False

#Comment the following line if you want to use captcha in the login form
auth.settings.login_captcha = False

#Setup your smtp server
#mail = auth.settings.mailer
#mail.settings.server = 'smtp.gmail.com:587'
#mail.settings.sender = 'xx@gmail.com'
#mail.settings.login = 'username:password'


if db(db.auth_user.id > 0).isempty():
    id_user = db.auth_user.insert(
            username = 'admin',
            password = db.auth_user.password.validate('admin')[0],
            email = 'changeme@waf2py.org',
            )
