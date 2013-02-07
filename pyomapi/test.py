#!/usr/bin/python2.4
import omapi

a=omapi.Omapi("10.1.23.3",7911,"OMAPI","dGVzdGtleQ==")

mac=a.lookup_mac("10.4.254.255")

print "mac=",mac

ip=a.lookup_ip(mac)

print "ip=",ip

print "adding host"
a.add_host("10.4.255.252","00:01:02:03:04:05")
print "deleting host"
a.del_host("00:01:02:03:04:05")
