logfireht
=========

A real-time HTTP access log monitoring tool.


Requirements
------------

* Python 2.7
* CherryPy for web frontend
* Jinja2 for web frontend
* pygeoip for IP country lookups
* GeoIP.dat database from http://www.maxmind.com/app/geoip_country


Getting Started
---------------

Parsing and printing statistics for the example log file:

    ./logfireht.py examples/example_access.log

Monitoring two log files (-t: tail, -f: follow) with web frontend (-s: start HTTP server on port 8081):

    ./logfireht.py -tfs /path/to/access1.log /another/path/to/access2.log


Configuration
-------------

Currently only a single webserver log format is supported.
The webserver configuration (e.g. port number) is done by editing site.conf.
To customize what IPs/URLs/UAs are used internally (e.g. load balancer IP, user agent used by monitoring scripts)
you can put a JSON config file such as example/logfirehtrc in ~/.logfirehtrc or /etc/logfirehtrc.


Thanks
------

Great FamFamFam icons (e.g. flags) by Mark James (http://www.famfamfam.com/lab/icons/silk/).
FamFamFam Silk icons are licensed under a Creative Commons Attribution 2.5 License (http://creativecommons.org/licenses/by/2.5/).

