#!/bin/bash
for x in $(find /opt/bochai/pcaps -name *snort*.14*); do mv $x $x.pcap; done
find /opt/bochai/pcaps -name *snort*.14* > /opt/bochai/output/pcap.inventory
for x in $(cat /opt/bochai/output/pcap.inventory); do redis-cli -h 10.1.84.31 RPUSH defaultdb $x; done
