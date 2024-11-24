#!/bin/bash

# Download the URLs listed in data/interim/jars/dl.txt using aria2c
# c: Continue downloading a partially downloaded file. Use this option to resume a download.
# i: Specifies an input file with listed URIs to download.
aria2c -c true -i ../data/interim/jars/dl.txt