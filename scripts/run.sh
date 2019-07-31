#!/bin/bash
cmake ..
make
rm /dev/shm/*
rm /dev/mqueue/*
src/liu_client
