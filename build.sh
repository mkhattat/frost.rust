#!/bin/bash

cargo build --release
cp target/release/libgencode.dylib ../../frost2/lib 
cp target/release/key-1 ../../frost2/lib 
cp target/release/key-2 ../../frost2/lib 
cp target/release/key-3 ../../frost2/lib 
cp target/release/key-4 ../../frost2/lib 
cp target/release/key.pub ../../frost2/lib 
