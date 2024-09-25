from threading import Thread
from statsmodels.tsa.stattools import grangercausalitytests
import pyshark
import pandas as pd
import math
import datetime
import subprocess
import sys
import read_accel
import time
from matplotlib import pyplot as plt


TIMEOUT = 50 #seconds to capture/record video

def sniff(interface):

    output_file = "/tmp/mycapture.pcap"
    command = f"sudo tshark -i {interface} -a duration:{TIMEOUT} -F pcap -w {output_file}" 
    subprocess.run(command.split(" "))
    
    print("Sniff terminated 👃⚪")
    print("Elaborating data (may take some time)...")
    
    capture = pyshark.FileCapture(output_file)
    capture.load_packets()
    
    sources = {}
    start_time = int(float(capture[0].sniff_timestamp))

    i = 0
    for frame in capture:
        print(i, "/", len(capture), end="\r")
        i += 1
        try:
            sa = frame.wlan.get("sa")
            if not sa: #some packets do not have 'sa' field but 'ta' for reasons?
                sa = frame.wlan.get("ta")
                if not sa:
                    continue #we don't have a valid source address
            fl = int(frame.length)
            _time = int(float(frame.sniff_timestamp))

            if sources.get(sa): #source address
                if _time - sources[sa]["time"] == 0:

                    sources[sa]["bytes_per_seconds"][sources[sa]["time"] - start_time] += fl
                elif _time - sources[sa]["time"] == 1:
                    sources[sa]["time"] = _time
                    sources[sa]["bytes_per_seconds"].append(fl)
                else: 
                    for i in range(sources[sa]["time"], _time):
                        sources[sa]["bytes_per_seconds"].append(0)
                    sources[sa]["time"] = _time
                    sources[sa]["bytes_per_seconds"].append(fl)
            
            else:
                sources[sa] = {
                    "bytes_per_seconds": [int(frame.length)],
                    "time": int(float(capture[0].sniff_timestamp))
                    }
        except Exception as e:
            pass
        
        
    
    return sources
    
if len(sys.argv) < 2:
    print("Wrong number of argumens!")
    print(f"Usage: {sys.argv[0]} network_card device")
    print(f"e.g.: {sys.argv[0]} eth0 192.168.1.2:5555")
    sys.exit(1)

card  = sys.argv[1]
device = sys.argv[2]

command = f"./list_channels.sh {card}"
channels = subprocess.run(command.split(" "), capture_output=True) 

channels = str(channels.stdout) 

channels = channels.split("\\n"); channels = channels[0:-1]

channels[0] = channels[0][ (len(channels[0])-1) : len(channels[0]) ]

print(f"{len(channels)} channels found!")

read_accel.connect2device(device)
read_accel.setup()
read_accel.runscript()

sniffed_channels = []

for channel in channels:
    print("🔍 Start monitoring on channel", channel)
    #now we lose connection to the device
    command = f"airmon-ng start {card} {channel}"

    if not card.endswith("mon"):
        card += "mon"
    
    subprocess.run(command.split(" "), stdout=subprocess.DEVNULL)  

    sniff_data = sniff(card) 

    sniffed_channels.append(sniff_data) 
    input("\nPress enter twice to continue")

print("Wireless data collected; stopping the capture...")
command = f"airmon-ng stop {card}" #stop the capture and reconnect to wifi
subprocess.run(command.split(" "), stdout=subprocess.DEVNULL) 
print("Riconnecting to the network...")
time.sleep(5) ; #some time is needed to reconnect to the network
print("Collecting ground sensor data...")
read_accel.connect2device(device) #reconnect to android device
read_accel.killscript() # stop the script 
accel_data = read_accel.get_data() #collect the data


for channel in sniffed_channels:
    for spy_device in channel:
        a_data = []
        timestamp = channel[spy_device]["time"] - TIMEOUT #this is needed since timestamp corresponds to the last timestamp, we need the first
        j = 0 #index for accel data
        for a in accel_data:
            if a.get(timestamp):
                break
            j += 1
        
        packet_data = channel[spy_device]["bytes_per_seconds"]

        if j+len(packet_data) < len(accel_data):
            for i in range(j, j+len(packet_data)):
                a_data.append(list(accel_data[i].values())[0])
        else:
            continue #not enough data
        
        plt.plot(range(len(packet_data)), packet_data)
        plt.savefig(spy_device + ".png")

        plt.clf()

        plt.plot(range(len(a_data)), a_data)
        plt.savefig(spy_device + "_accel.png")

        plt.clf()

        d = {'frame': a_data, 'packet': packet_data}
        df = pd.DataFrame(data=d)
        try:
            gtests = grangercausalitytests(df[['frame', 'packet']], maxlag=5, verbose=False)
            #lag = 1
            for lag in gtests:
                if (gtests[lag][0]["ssr_ftest"][1] < 0.08):
                    print(f"someone monitoring you! (lag{lag}, device: {spy_device})")
                    
        except Exception as e:
            
            pass

