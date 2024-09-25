#module to read the smartphone accelerometer
import subprocess
import math
from datetime import datetime
from matplotlib import pyplot as plt

TIMEOUT = 20
folder = "/sdcard/snoopdogg/" 
out_file = f"{folder}accel.out"
runscript_name = "run_android.sh"
script_name = "android.sh"

cmd_mkdir = f"adb shell mkdir {folder}"                #create working directory on device
cmd_rm = f"adb shell rm {out_file}"                    #delete output file on device
cmd_push = f"adb push {script_name} {folder}"          #load script 2 on device
cmd_run_push = f"adb push {runscript_name} {folder}"   #load script 1 on device
cmd_script = f"adb shell sh {folder}{runscript_name}"  #launch script and print pid on device
cmd_polish = "sh output.sh"                            #download and clean the output file

setup_cmd = [cmd_mkdir, cmd_rm, cmd_push, cmd_run_push]

def setup():
    for cmd in setup_cmd:
        subprocess.run(cmd.split(" "))

def runscript():
    subprocess.Popen(cmd_script.split(" "))
    print("Started process on device")

def killscript():
    cmd_kill = f"adb shell kill `cat {folder}pid`"
    subprocess.run(cmd_kill.split(" "))


def connect2device(ip):
    cmd_connect = f"adb connect {ip}"
    subprocess.run(cmd_connect.split(" "))

def get_data():
    subprocess.run(cmd_polish.split(" "))
    file = open("accel.out")
    data = file.readlines()
    file.close()

    now = datetime.now()
    today = now.strftime("%Y-%m-%d")

    readings_ts = []
    accel_per_sec = 0
    sec = -1
    r_counter = 0
    for line in data:
        if line.startswith("ts"):
            r_counter += 1
            l = line.split(",")
            
            ts = l[1].replace(" wall=", "") ; ts = ts[:ts.find(".")]
            ts = int(datetime.fromisoformat(f"{today}T{ts}").timestamp()) #format 2022-04-02T11:12:13 to unix epoch timestamp

            if sec == -1:
                # sec = int(float(l[0].replace("ts=", "")))
                sec = ts
            
            #_s = int(float(l[0].replace("ts=", "")))
            
            if ts < sec: #condition is needed because if there is no new data, accel sensors gives old data
                continue
            elif ts > sec: 
                # ts = l[1].replace(" wall=", "") ; ts = ts[:ts.find(".")]
                # ts = int(datetime.fromisoformat(f"{today}T{ts}").timestamp()) #format 2022-04-02T11:12:13 to unix epoch timestamp
                d = {} ; d[ts] = accel_per_sec/r_counter
                readings_ts.append(d)
                

                r_counter = 0
                accel_per_sec = math.sqrt(float(l[2])**2 + float(l[3])**2 + float(l[4])**2)
                sec = ts
            else:
                accel_per_sec += math.sqrt(float(l[2])**2 + float(l[3])**2 + float(l[4])**2)

    return readings_ts