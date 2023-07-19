#!/bin/bash

yum install cmake3 libunwind-devel -y &&

# asio
tar xvf asio-1.28.0.tar.gz2 && 
cd asio-1.28.0 && 
make -j8 && make install

# gflags
tar xvf gflags-2.2.2.tar.gz &&
cd gflags-2.2.2 &&
mkdir build && cd build &&
cmake3 -DBUILD_SHARED_LIBS=ON .. &&
make -j8 && make install

# glog
tar xvf glog-0.6.0.tar.gz &&
cd glog-0.6.0 &&
mkdir build && cd build &&
cmake3 .. &&
make -j8 && make install

# protobuf
tar xvf protobuf-23.4.tar.gz.2 &&
cd protobuf-23.4 &&
mkdir build && cd build &&
cmake3 -DABSL_PROPAGATE_CXX_STD=ON .. &&
make -j8 && make install

# googletest
tar xvf googletest-1.13.0.tar.gz && 
cd googletest-1.13.0 && 
mkdir build && 
cd build && 
cmake3 .. && 
make -j8 && make install

