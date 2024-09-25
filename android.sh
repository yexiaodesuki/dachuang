#!/bin/sh

while true ; do
	dumpsys sensorservice | grep -A50 "accel:" >> /sdcard/snoopdogg/accel.out
done
