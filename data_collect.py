from scapy.all import *          # 导入scapy库中的所有模块
from datetime import datetime    # 导入datetime模块，用于处理日期和时间
import time                      # 导入time模块，用于处理时间相关的操作
from threading import Thread     # 导入Thread模块，用于创建多线程
import subprocess, shlex    # 导入subprocess、shlex模块，用于运行外部命令
import threading                 # 再次导入threading模块（此处重复导入）
import pandas as pd              # 导入pandas库，用于处理数据表格
import csv                       # 导入csv模块，用于处理CSV文件
import numpy as np               # 导入numpy库，用于处理数值计算
import os                       # 导入os模块，用于操作系统相关操作
import copy                      # 导入copy模块，用于对象复制
# from scipy import all             # 注释掉导入scipy库all模块的语句
# from scipy.interpolate import griddata, interp2d  # 注释掉导入scipy库interpolate模块中griddata和interp2d函数的语句
import math                      # 导入math模块，用于数学计算
import pandas as pd              # 再次导入pandas库（此处重复导入）
# from scipy.optimize import curve_fit  # 注释掉导入scipy库optimize模块中curve_fit函数的语句
# from mac_vendor_lookup import MacLookup  # 导入mac_vendor_lookup库中的MacLookup模块，用于查询MAC地址对应的厂商信息


def Change_Freq_channel(channel_c):  # 定义名为Change_Freq_channel的函数，参数为channel_c
    print('Channel:',str(channel_c))  # 打印当前频道号
    command = 'iwconfig wlan0mon channel '+str(channel_c)  # 构建设置频道命令字符串
    command = shlex.split(command)  # 使用shlex.split将命令字符串分割成列表
    subprocess.Popen(command,shell=False)  # 使用subprocess.Popen以非交互模式运行命令


def method_filter_HTTP(pkt):  # 定义名为method_filter_HTTP的函数，参数为pkt
    missed_count = 0  # 重新初始化未成功写入次数计数器为0（此处与全局变量同名，可能产生混淆）
    cur_dict={}  # 定义字典cur_dict，用于存储当前包信息
    cur_dict['mac_1']  =pkt.addr1  # 将pkt的addr1属性值存入字典cur_dict['mac_1']
    cur_dict['mac_2']  =pkt.addr2  # 将pkt的addr2属性值存入字典cur_dict['mac_2']
    cur_dict['rssi'] = pkt.dBm_AntSignal  # 将pkt的dBm_AntSignal属性值存入字典cur_dict['rssi']

    if True:  # 注释掉无条件分支（无实际作用）
    # if cur_dict['mac_1']==router_mac:  # 检查当前包源MAC地址是否与路由器MAC地址相同
    # if cur_dict['mac_2']==dev_mac or cur_dict['mac_1']==dev_mac:  # 检查当前包目的MAC地址是否与设备MAC地址相同
        print(pkt.show)  # 打印当前包详细信息

        # print(pkt.show())  # 注释掉此行（与上一行功能重复）
        # ()+1  # 注释掉此行（无实际作用）

        file_object = open('rssi.txt', 'a')  # 打开文件（以追加模式），并将文件对象赋值给file_object变量
        print(cur_dict)  # 打印当前包信息字典
        try:
            to_write=str(datetime.now().strftime("%d/%m/%Y %H:%M:%S.%f")) + " " + cur_dict['mac_1']+","+cur_dict['mac_2']+","+str(cur_dict['rssi'])+"\n"  # 构建待写入字符串
            file_object.write(to_write)  # 将构建的字符串写入文件
            file_object.close()  # 关闭文件对象
        except Exception as e:  # 捕获并处理写入文件时可能出现的异常
            print("E\t",e,missed_count)  # 输出错误信息及计数器值
            # print(pkt.show2())  # 注释掉此行（与上文功能重复且未定义pkt.show2方法）
            # ()+1  # 注释掉此行（无实际作用）
            missed_count+=1  # 计数器递增

    return 0  # 函数返回0

def data_collect():
    locky = threading.Lock()         # 创建一个线程锁对象

    router_mac = "b4:b0:24:f2:cd:18"  # 声明路由器MAC地址
    dev_mac = "78:df:72:24:69:4d"  # 声明设备MAC地址

    filename = 'rssi.txt'  # 定义RSSI数据文件名
    file_object = open('rssi.txt', 'w')  # 打开文件（以写入模式），并将文件对象赋值给file_object变量
    file_object.close()  # 关闭文件对象

    missed_count = 0  # 初始化未成功写入次数计数器为0
    for channel_c in range(1,15):  # 注释掉此行（被下方循环覆盖）
    # for channel_c in range(1, 3):  # 循环遍历频道号1和2

        print("Channel\t", channel_c)  # 打印当前频道号
        t = Thread(target=Change_Freq_channel, args=(channel_c,))  # 创建线程对象，目标为Change_Freq_channel函数，参数为channel_c
        t.daemon = True  # 设置线程为守护线程
        locky.acquire()  # 获取线程锁
        t.start()  # 启动线程
        # time.sleep(10)  # 注释掉此行（暂停线程10秒）
        t = AsyncSniffer(iface="wlan0mon", prn=method_filter_HTTP,
                         store=1)  # 创建AsyncSniffer对象，监听接口"mon0"，处理函数为method_filter_HTTP，不存储包
        t.start()  # 启动AsyncSniffer对象
        time.sleep(40)  # 暂停主线程40秒
        t.stop()  # 停止AsyncSniffer对象
        locky.release()  # 释放线程锁
        # break  # 结束循环
        # 访问存储的数据包
        packets = t.results
        # 生成文件名，例如 'captured_packets_0.pcap', 'captured_packets_1.pcap', ...
        filename = f'captured_packets_{channel_c}.pcap'
        # 将捕获的数据包写入 pcap 文件
        wrpcap(filename, packets)

    rssiFile = open("./rssi.txt")  # 打开文件（默认模式），并将文件对象赋值给rssiFile变量
    rssiData = rssiFile.read()  # 读取文件内容并赋值给rssiData变量

    # print(rssiData)  # 注释掉此行（打印rssiData内容）
    # 创建一个空列表，用于存储解析后的RSSI数据
    dflist = []

    # 遍历rssiData中的每一行（已按行分割）
    for rssi in rssiData.splitlines():
        # 创建一个字典，用于存储当前行的数据
        d1 = {}

        # 使用空格将当前行分割成多个部分，存储在列表spl中
        spl = rssi.split(" ")

        # 打印分割后的部分
        print(spl)

        # 从spl的第三个元素（索引为2）开始，使用逗号进行分割，结果存储在ost列表中
        ost = spl[2].split(",")

        # 打印分割后的部分
        print(ost)

        # 将spl的第一个元素（日期）赋值给字典的'date'键
        d1['date'] = spl[0]

        # 将spl的第二个元素（时间）赋值给字典的'time'键
        d1['time'] = spl[1]

        # 将ost的第一个元素（目的MAC地址）赋值给字典的'dst'键
        d1['dst'] = ost[0]

        # 将ost的第二个元素（源MAC地址）赋值给字典的'src'键
        d1['src'] = ost[1]

        # 将ost的第三个元素（RSSI值）赋值给字典的'rssi'键
        d1['rssi'] = ost[2]

        # 打印当前行解析后的字典
        print(d1)

        # 将当前行解析后的字典添加到dflist列表中
        dflist.append(d1)

    # 将解析后的RSSI数据列表转换为Pandas DataFrame对象
    df = pd.DataFrame(dflist)

    # 打印转换后的DataFrame对象
    print(df)

    # 将DataFrame对象保存为CSV文件，文件名为'rssi_mod.csv'，不包含行索引
    df.to_csv('rssi_mod.csv', index=False)
