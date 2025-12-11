#!/bin/bash
echo "cp files locally for build"
cp conf/capnc.conf docker/
touch docker/capnc.log
cp bin/capnc.py docker/
echo "build image and push"
docker build docker
docker push bochai/capncrunch:latest
