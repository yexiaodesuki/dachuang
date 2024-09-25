#!/bin/bash

# 清除之前的accel.out文件
rm accel.out

# 从设备的/sdcard/snoopdogg目录下拉取accel.out文件，并重命名为accel.raw
adb pull /sdcard/snoopdogg/accel.out accel.raw

# 对accel.raw文件进行处理，移除无用信息并转换格式，输出结果到accel.out文件同时在终端显示
sed 's/.*(//g' accel.raw | sed 's/)/,/g' | tee accel.out > /dev/null
