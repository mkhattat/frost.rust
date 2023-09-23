#!/bin/bash


# ./target/release/gencode -T 4 -N 4 -P 0 -p 8877 -a "192.168.0.138,192.168.0.146,192.168.0.153,192.168.0.154"
./target/release/gencode -T 2 -N 2 -P 0 -p 8877 -a "192.168.0.138,192.168.0.146"
