#!/bin/bash

cargo build --release
cp target/release/libgencode.dylib ../../frost2/lib 
cp key-1 ../../frost2/
cp key-2 ../../frost2/
cp key-3 ../../frost2/
cp key-4 ../../frost2/
cp key.pub ../../frost2/
