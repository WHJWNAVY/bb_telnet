#!/bin/sh

rm -rf build; mkdir build && cd build
cmake ../src && make && cp telnet ../; cd -