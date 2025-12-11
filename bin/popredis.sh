#!/bin/bash
for x in $(find /home/klg/BOC/pcaps -name *snort*.14*); do mv $x $x.pcap; done
find /home/klg/BOC/pcaps -name *snort*.14* > /home/klg/BOC/pcaps/pcap.inventory
for x in $(cat /home/klg/BOC/pcaps/pcap.inventory); do redis-cli -h 10.1.145.31 RPUSH defaultdb $x; done

