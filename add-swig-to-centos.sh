#!/usr/bin/env bash
# Script to build swig on centos6.
# note; 'yum install swig' delivers swig 1.0. Cannot use.
git clone https://github.com/swig/swig.git && \
    cd swig && \
    ./autogen.sh && \
    ./configure && \
    ./make install
