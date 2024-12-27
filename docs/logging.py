# Predator logging and forward

## Local
Local logging is stored in predator home (example /opt/predator) in ./var/log directory; in detail:

- **predator.log**: log for the health status thread
- **predator_boom.log**: log for general exception
- **predator_dns.log**: log for DNS request
- **predator_dummy.log**: log for DUMMY module
- **predator_l7.log**: log for L7 requested intercepted through L4 module (unencrypted connections)
- **predator_library.log**: log for internal information server
- **predator_management.log**: log for API module
- **predator_proxy.log**: log for Proxy module
- **predator_sniffers.log**: log for L4 module
- **predator_std.log**: log for STDOUT (if enabled)
- **predator_threats.log**: log for threats raised

Note the initial log level has set to INFO for all loggers as reported in config.py file.

# Forward
Predator can forward threats log to third-party software such:

- **syslog**: if SEND_TO_SYSLOG is set to True, log are written into local syslog
- **elasticsearch**: if SEND_TO_ES is set to True, log are sent to Elasticsearch server

Refer to [config.py](./config.md) documentation.
