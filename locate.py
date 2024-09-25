import os
import subprocess
import time
import pandas as pd
from statsmodels.tsa.stattools import grangercausalitytests

# 函数：启动网卡
def start_network_card(interface='wlan0'):
    try:
        subprocess.run(['airmon-ng', 'start', interface], check=True)
        subprocess.run(['ifconfig', 'wlan0mon', 'up'], check=True)
        print("Network card started successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error starting network card: {e}")

# 函数：使用tshark抓包
def capture_packets(area):
    output_file = f'./result/area{area}.pcap'
    try:
        subprocess.run(['tshark', '-i', 'wlan0mon', '-w', output_file], check=True, timeout=60)
        print(f"Packets captured for area {area} successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error capturing packets for area {area}: {e}")
    except subprocess.TimeoutExpired:
        print(f"Packet capture for area {area} timed out.")

# 函数：读取IMU数据
def read_imu_data(file_path='imu.txt'):
    try:
        imu_data = pd.read_csv(file_path, sep="\t")
        print("IMU data read successfully.")
        return imu_data
    except Exception as e:
        print(f"Error reading IMU data: {e}")
        return None

# 函数：格兰杰因果关系测试
def granger_causality_test(imu_data, packet_data, max_lag=10):
    data = pd.concat([imu_data, packet_data], axis=1)
    test_result = grangercausalitytests(data, max_lag, verbose=False)
    # 返回F值
    f_values = [result[0]['ssr_ftest'][0] for result in test_result.values()]
    return max(f_values)

def main():
    # 启动网卡
    start_network_card()

    # 读取IMU数据
    imu_data = read_imu_data()
    if imu_data is None:
        return

    # 对区域1-9（除了区域5）进行抓包并进行格兰杰因果关系测试
    max_granger_value = -float('inf')
    max_granger_area = None
    
    for area in range(1, 10):
        if area == 5:
            continue
        capture_packets(area)
        
        # 读取抓包文件并进行处理
        packet_data = process_packet_file(f'./result/area{area}.pcap')
        if packet_data is None:
            continue
        
        # 构建格兰杰因果关系
        granger_value = granger_causality_test(imu_data, packet_data)
        print(f"Granger causality F-value for area {area}: {granger_value}")

        # 更新最大格兰杰因果关系的区域
        if granger_value > max_granger_value:
            max_granger_value = granger_value
            max_granger_area = area

    print(f"Area with the highest Granger causality: Area {max_granger_area} with F-value {max_granger_value}")

# 函数：处理抓包文件
def process_packet_file(file_path):
    try:
        packet_data = pd.read_csv(file_path)
        # 假设你对packet_data有特定的处理需求
        print(f"Packet data read and processed for {file_path}.")
        return packet_data
    except Exception as e:
        print(f"Error processing packet file {file_path}: {e}")
        return None

if __name__ == "__main__":
    main()
