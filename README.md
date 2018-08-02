
# Waf2Py [Beta]
Waf2Py is a nice and easy to use web interface for modsecurity running on nginx. Waf2Py is free and powered by Web2Py that controls modsecurity and nginx configuration in an easy way, allowing you to configure protection for any webapplication in just minutes.

## What can I do with this interface?

- Create a site in just minutes
- Create global or local exclusions with just 2 clicks
- Add virtual interfaces
- Create static routes for the desired app
- Check debug, access, error and audit logs in an easy way
- Download logs
- Check the stats for every application with nice graphics
- Disable/Enable protection with just 1 click
- Restrict paths or files
- Insert headers



## Installing steps

```
git clone https://github.com/ITSec-Chile/Waf2Py.git
cd Waf2py
su root
chmod +x Install.sh
./Install.sh

```

## Creating a website
```
1 - Create a virtual IP
      --> Interfaces menu

2 - Create a new app
      --> Click "check" button
      --> Click "Deploy" button

3 - Configure the new app
      --> Websites running menu
      --> Click over the application
      --> Configure the backend
      --> Configure ports
      --> Configure certificates if 443 port is enabled
      --> Choose a virtual ip (previusly created on Interfaces menu)
      --> Press the "play" button to enable the new app
      --> Done.
```

## Built With

* [Web2Py](http://www.web2py.com/) - The web framework used
* [Modsecurity](https://www.modsecurity.org/) - WAF Engine
* [Nginx](https://www.nginx.com/) - Reverse proxy
* [Apache](https://httpd.apache.org/) - Webserver to hold Web2Py
* [AdminLTE](https://adminlte.io/) - Template in the web interface


## About this bundle
```
Works in Debian 9 and 8.
Components for this build:
Nginx version: openresty/1.9.7.4
ModSecurity for nginx (STABLE)/2.9.0 (http://www.modsecurity.org/); 
Rules: OWASP_CRS/2.2.9.

We have pre-compiled openresty and modsecurity in debian 8 & 9, they are compressed here in this repo.
There is no modification to the binaries.
```

<b>Note 1</b>: By now not all options of nginx and modsecurity are implemented with nice switches. Advanced configurations can be made throught the "expert configuration" tab.

<b>Note 2</b>: This implementation works with modsecurity 2.9.0. We decided to first release a version for the “old” modsecurity. We will soon release the interface for modsecurity 3 :). Just wait for it!

<b>Note 3</b>: Every action you perform in the web interface will be saved and logged. nginx will check its configuration syntax first, if the configuration is not correct, nginx will not be reloaded. If you do something wrong in the configuration files, it doesn’t matter. Nginx will reload and apply the new changes only if the syntax of the configuration files is correct.

### If you want to compile nginx and modsecurity yourself, please see the wiki. You will have to maintain certain directories
* <a href="https://github.com/ITSec-Chile/Waf2Py/wiki">Wiki</a>

## Support
We invite you to test and support this development to make something powerful and free.

## License

The following files are pending of license

```
Waf2Py/modules/changeconfig.py
Waf2Py/modules/log_indexer.py
Waf2Py/modules/logs.py
Waf2Py/modules/manual_reload.py
Waf2Py/modules/network.py
Waf2Py/modules/stuffs.py
Waf2Py/scripts/check_services.py
Waf2Py/scripts/clean_logs.sh
Waf2Py/scripts/cleaning.log
Waf2Py/scripts/get_apps.py
Waf2Py/scripts/index_logs_files.py
Waf2Py/scripts/log_rotation.sh
Waf2Py/scripts/names
Waf2Py/scripts/remove_tmp.sh
Waf2Py/controllers/Logs.py
Waf2Py/controllers/Network.py
Waf2Py/controllers/Rewrite.py
Waf2Py/controllers/SSL.py
Waf2Py/controllers/default.py


Waf2Py/views/Network/AddVirtualIps.html
Waf2Py/views/Network/Interfaces.html
Waf2Py/views/Network/Routes.html
Waf2Py/views/Network/VirtualIps.html

Waf2Py/views/Logs/AccessLogs.html
Waf2Py/views/Logs/AppLogs.html
Waf2Py/views/Logs/DebugLogs.html
Waf2Py/views/Logs/DownloadLogs.html
Waf2Py/views/Logs/ErrorAppLogs.html
Waf2Py/views/Logs/ErrorLogs.html
Waf2Py/views/Logs/ExcludeManual.html
Waf2Py/views/Logs/GeneralDenyLogs.html
Waf2Py/views/Logs/RuleList.html
Waf2Py/views/Logs/Summary.html
Waf2Py/views/Logs/WafLogs.html
Waf2Py/views/Logs/WafLogs_frame.html

Waf2Py/views/default/AccessLogs.html
Waf2Py/views/default/CreateNewApp.html
Waf2Py/views/default/Dashboard.html
Waf2Py/views/default/GeneralAccessLogs.html
Waf2Py/views/default/GeneralErrorLogs.html
Waf2Py/views/default/Manage.html
Waf2Py/views/default/ProdEdit
Waf2Py/views/default/ProdEdit.html
Waf2Py/views/default/RawLogs.html
Waf2Py/views/default/WafLogs.html
Waf2Py/views/default/Websites.html
Waf2Py/views/default/index.html
Waf2Py/views/default/new_app.html
Waf2Py/views/default/user.html

```
## RoadMap

### Stage I

```
Move to ModSecurity 3
```

### Stage II 

```
Server Cloacking (Header Rewrite)
GeoIP Blocking
IP Reputation 
Cookie and URL Encryption
More cool features
```

### Stage II
```
Complete the pluging System for add new features

```

