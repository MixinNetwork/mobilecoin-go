#!/bin/bash

cd mobilecoin/libmobilecoin
make
cp out/ios/include/* ../../include
cd ..
cp target/x86_64-apple-darwin/mobile-release/libmobilecoin.a ../include

