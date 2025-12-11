FROM debian:bookworm
FROM python:3.14.2

RUN set -ex \
    && sed -i -- 's/Types: deb/Types: deb deb-src/g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
               build-essential \
               python3 \
               cdbs \
               devscripts \
               equivs \
               fakeroot \
    && apt-get clean \
    && rm -rf /tmp/* /var/tmp/*

#Create needed directories
RUN mkdir -p /opt/capnc/{conf,bin,output,logs}
RUN mkdir -p /opt/capnc/output/full

#Copy configuraiton files
COPY  capnc.conf /opt/capnc/conf/capnc.conf
COPY  capnc.py /opt/capnc/bin/capnc.py
COPY  capnc.log /opt/capnc/logs/capnc.log
RUN pip install pypcapkit redis configparser
#Configure PIP with redis and pcapkit

RUN python3 /opt/capnc/bin/capnc.py
