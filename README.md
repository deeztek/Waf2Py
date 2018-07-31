
# Waf2Py
Waf2Py is a nice and easy to use web interface for modsecurity and nginx implementation. Waf2Py is free and run under Web2Py that controls modsecurity and nginx configuration in a easy way, allowing to configure any application in just minutes.

## What can I do with this interface?

- Create a site in just minutes,
- Create global or local exclusions with just 2 clicks!
- Add virtual interfaces
- Create static routes for the desired app.
- Check debug, access, error and audit logs in a easy way,
- Download logs
- Check the stats for every application with nice graphics
- Disable/Enable protection with just 1 click.



## Installing steps

```
git clone https://github.com/ITSec-Chile/Waf2Py.git
cd Waf2py
su root
Chmod +x Install.sh
./Install.sh

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

We have previusly compiled openresty and modsecurity in debian 8 and 9, and they are compreses here in this repo.
There is no modification to the binaries
```

<b>Note 1</b>: By now not all options of nginx and modsecurity are implemented whit nice switches, advanced configurations can be maded throught the "expert configuration" tab.

<b>Note 2</b>: This implementation works with modsecurity 2.9.0, we decided to release first this version for the “old” modsecurity. We are gonna release soon the interface for modsecurity 3 :). Just wait for it!

<b>Note 3</b>: Everytime that you perform an action in the web interface will be saved, logged and nginx will check his configuration syntax first, if configuration is not ok, nginx will not be reloaded, so if you do something wrong with the configuration files, it doesn’t matter, only if syntax is ok nginx will be reload his configuration applying the news changes.

### If you want to compile nginx and mod security please see the wiki, you will have to maintain certain directories
* <a href="https://github.com/ITSec-Chile/Waf2Py/wiki">Wiki</a>

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


