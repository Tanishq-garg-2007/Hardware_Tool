#!/bin/bash

# Default parameters
speed="8000"
firm_name="dump.bin"
firm_dir="."

if [ $# -ge 1 ] && [ -n "$1" ]; then
    speed="$1"
fi
if [ $# -ge 2 ] && [ -n "$2" ]; then
    firm_name="$2"
fi
if [ $# -ge 3 ] && [ -n "$3" ]; then
    firm_dir="$3"
fi

mkdir -p "$firm_dir"
out_path="$firm_dir/$firm_name"

echo "[INFO] Running flashrom dump at speed $speed to $out_path..."
device_output=$(flashrom -p "linux_spi:dev=/dev/spidev0.0,spispeed=$speed" -r "$out_path" 2>&1)
ret=$?

echo "$device_output"

if [ $ret -eq 0 ] && [[ "$device_output" == *"Reading flash... done."* ]]; then
    echo "success reading flash"
    exit 0
else
    echo "failed dump"
    exit 1
fi

