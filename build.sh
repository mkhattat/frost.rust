#!/bin/bash

cargo build --release
cp target/release/libgencode.dylib ../../frost2/lib 
cp target/release/libgencode.dylib ../../fabric/fabric-samples/asset-transfer-basic/application-gateway-go/lib
# cp key.pub ../../frost2/
# cp key-1 ../../frost2/
# cp key-2 ../../frost2/
# cp key-3 ../../frost2/
# cp key-4 ../../frost2/
