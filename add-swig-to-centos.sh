#!/usr/bin/env sh
# Script to build swig on centos6.
git clone https://github.com/swig/swig.git && \
    cd swig && \
    ./autogen.sh && \
    ./configure && \
    ./make install
