#!/bin/bash

gcc filter.c -Wall -lnetfilter_queue --std=gnu11 -o SDP-Filter
