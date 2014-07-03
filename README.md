dnsbff
======

DNS BFF listens to your network interface for outgoing SERVFAILS.
Once it hits a threshold it will add the domain to a zone file so you can deny additional queries.

Setup instructions are bind specific but can be tailored to other dns servers as well.

Create an empty zone file /var/named/chroot/var/named/blank-zone with the contents something like:
```
@ 10800 in soa . . ( 1 3600 1200 604800 10800 )
@ 10800 IN NS .
```

Add this line to your named.conf:
include "/etc/named/bad-zones.conf";

You may need to adjust paths in code to suite your seutp.
I'll make these configurable later.

Look at the section labeled "Knobs"

 VARIABLES             | DESC
 :---------------------| :-----------------------------------------------------------------------------
 $DNS_IP               | should be set to your DNS servers ip address
 $MIN_BLOCK_COUNT      | is the number of unique hosts of a domain to gather before deciding to block
 $MAX_CACHE_TIME       | is how long a host can stay in the cache before being purged
 $MINDOTS              | is the minimum nomber of parts a domain must have to be acted on. 3 dots means look at dlkfjldfjk.foo.bar.com not foo.bar.com
 $dev                  | is your ethernet device
 $filter_str           | you shouldn't need to change this unless you are looking for other things than SERVFAIL
 $bad_zones_file       | zone file to write bad domains to be blocked.
 $MAX_CHECK_LOOP_COUNT | How often to check and add bad domains. Every X number of packets
 $MAX_CACHE_LOOP_COUNT | How often to clean cache. Every X number of packets


running with ./dnsbff.pl --debug will keep in foreground and output logging to the screen.
logging is also logged to local6 syslog  while running.

You may need to install various perl modules. I'm running on CENTOS 5. Centos RPMS plus EPEL had everything I needed.

Thoughts / Comments welcome.

William - Sonic.net
