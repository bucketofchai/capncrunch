#!/usr/bin/python3
# bucket of chai / Dec 2025
# CapNCrunch: a scalable PCAP > JSON processor with outputs to Cribl/Splunk
# capnc.py: reads from the REDIS workqueue defined in conf/capnc.conf & by default runs a full_extract at the link layer to JSON
# currently ouputs to log file but will stream to Splunk/Cribl in future 

#Libraries
import os
import sys
import logging
import configparser
from pcapkit import extract
import redis
import uuid
import hashlib

#### A Simple Finite Work Queue with Redis Backend
# This work queue is finite: as long as no more work is added
# after workers start, the workers can detect when the queue is completely empty.
# The items in the work queue are assumed to have unique values.
# This object is not intended to be used by multiple threads concurrently.
# modified by boc from https://kubernetes.io/examples/application/job/redis/rediswq.py

class workqueue(object):
    def __init__(self, name, **redis_kwargs):
       """The default connection parameters are: host='localhost', port=6379, db=0

       The work queue is identified by "name".  The library may create other
       keys with "name" as a prefix.
       """
       self._db = redis.StrictRedis(**redis_kwargs)
       # The session ID will uniquely identify this "worker".
       self._session = str(uuid.uuid4())
       # Work queue is implemented as two queues: main, and processing.
       # Work is initially in main, and moved to processing when a client picks it up.
       self._main_q_key = name
       self._processing_q_key = name + ":processing"
       self._lease_key_prefix = name + ":leased_by_session:"

    def sessionID(self):
        """Return the ID for this session."""
        return self._session

    def _main_qsize(self):
        """Return the size of the main queue."""
        return self._db.llen(self._main_q_key)

    def _processing_qsize(self):
        """Return the size of the main queue."""
        return self._db.llen(self._processing_q_key)

    def empty(self):
        """Return True if the queue is empty, including work being done, False otherwise.

        False does not necessarily mean that there is work available to work on right now,
        """
        return self._main_qsize() == 0 and self._processing_qsize() == 0

    def _itemkey(self, item):
        """Returns a string that uniquely identifies an item (bytes)."""
        return hashlib.sha224(item).hexdigest()

    def _lease_exists(self, item):
        """True if a lease on 'item' exists."""
        return self._db.exists(self._lease_key_prefix + self._itemkey(item))

    def lease(self, lease_secs=60, block=True, timeout=None):
        """Begin working on an item the work queue.

        Lease the item for lease_secs.  After that time, other
        workers may consider this client to have crashed or stalled
        and pick up the item instead.

        If optional args block is true and timeout is None (the default), block
        if necessary until an item is available."""
        if block:
            item = self._db.brpoplpush(self._main_q_key, self._processing_q_key, timeout=timeout)
        else:
            item = self._db.rpoplpush(self._main_q_key, self._processing_q_key)
        if item:
            # Record that we (this session id) are working on a key.  Expire that
            # note after the lease timeout.
            # Note: if we crash at this line of the program, then GC will see no lease
            # for this item a later return it to the main queue.
            itemkey = self._itemkey(item)
            self._db.setex(self._lease_key_prefix + itemkey, lease_secs, self._session)
        return item

    def complete(self, value):
        """Complete working on the item with 'value'.

        If the lease expired, the item may not have completed, and some
        other worker may have picked it up.  There is no indication
        of what happened.
        """
        self._db.lrem(self._processing_q_key, 0, value)
        # If we crash here, then the GC code will try to move the value, but it will
        # not be here, which is fine.  So this does not need to be a transaction.
        itemkey = self._itemkey(value)
        self._db.delete(self._lease_key_prefix + itemkey)

# a generic log format function to ensure log consistency
def log(log_file, message):
    # Set up the logger
    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)
    # Create a file handler
    handler = logging.FileHandler(log_file)
    handler.setLevel(logging.DEBUG)
    # Create a formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    # Add the handler to the logger
    logger.addHandler(handler)
    # Log the message
    logger.info(message)

def read_capnc_conf(conf_file):
    config = configparser.ConfigParser()
    config.read(conf_file)          
        # Accessing configuration values from conf/capn.conf
    redis_host = config.get('redis_config', 'host')
    redis_port = config.get('redis_config', 'port')
    redis_queue_name = config.get('redis_config', 'workqueue')
        #pcap options
    pcap_layer = config.get('pcap_config', 'layer')
    pcap_output = config.get('pcap_config', 'output')
    pcap_format = config.get('pcap_config', 'format')
        #capnc settings
    log_file = config.get('capnc_config', 'log_file')
    scriptpath = config.get('capnc_config', 'log_file')
    return redis_host, redis_port, redis_queue_name, pcap_layer, pcap_output, pcap_format, log_file, scriptpath


# a full extract of the PCAP file read at the layer defined in the capnc.conf [pcap_config] section
def full_extract_to_json(pcap_file, pcap_layer, pcap_output, pcap_format):
    extract(fin=pcap_file, fout=pcap_output, format=pcap_format, files=True, layer=pcap_layer)
    log(fout,str())


if __name__ == "__main__":
    # Read the local config                                                  
    conf_file = "/opt/capnc/conf/capnc.conf"
    redis_host, redis_port, redis_queue_name, pcap_layer, pcap_output, pcap_format, log_file, scriptpath = read_capnc_conf(conf_file)
    sys.path.append(os.path.abspath(scriptpath))

    #connect to the Redis server defined in the capnc.conf
    q = workqueue(name=redis_queue_name, host=redis_host, port=redis_port)
    #capnc.log file connection messages
    message_sessionID = str("Worker with sessionID: " +  q.sessionID())
    message_queustate = str("Initial queue state: empty=" + str(q.empty()))
    log(log_file,message_sessionID)
    log(log_file,message_queustate)
    
    while not q.empty():
        item = q.lease(lease_secs=10, block=True, timeout=2)
        if item is not None:
            itemstr = item.decode("utf-8")
            full_extract_to_json(itemstr,pcap_layer,pcap_output,pcap_format)
            q.complete(item)
        else:
         log(log_file,str("Waiting for work"))
         log(log_file,str("Queue empty, exiting"))
                
