from scapy.all import rdpcap, PcapReader
from scapy.layers.dot11 import Dot11
import numpy as np
import os

# 假设这是我们在训练阶段标记的MAC地址和对应的标签
MAC_LABELS = {
    # "00:11:22:33:44:55": 0,  # 录音设备
    "78:df:72:24:69:4d": 1,  # 摄像头设备
    "a4:ef:15:a7:f8:33": 1,
    "94:f8:27:f7:de:7e": 1,
    "34:7d:e4:5a:2b:b0": 1,
    # "98:f1:12:2c:cd:db": 1
    # 添加更多的MAC地址和对应的标签
}


def extract_basic_features(packet):
    features = {
        'timestamp': packet.time,
        'size': len(packet),
        'src_mac': packet.addr2,
        'dst_mac': packet.addr1,
        'type': packet.type,
        'subtype': packet.subtype
    }
    return features


def group_by_mac_and_type(packets):
    grouped_packets = {}
    for packet in packets:
        key = (packet['src_mac'], packet['type'], packet['subtype'])
        if key not in grouped_packets:
            grouped_packets[key] = []
        grouped_packets[key].append(packet)
    return grouped_packets


def split_into_blocks(packets, block_size):
    # 将数据包分成大小为 block_size 的块
    blocks = []
    for i in range(0, len(packets), block_size):
        blocks.append(packets[i:i + block_size])
    return blocks


def calculate_features(grouped_packets, block_size):
    features = []
    all_mac_tp_count = sum(len(p) for p in grouped_packets.values())
    mac_all_tp_count = {}

    for (mac, tp, subtype), packets in grouped_packets.items():
        blocks = split_into_blocks(packets, block_size)
        for block in blocks:
            timestamps = [p['timestamp'] for p in block]
            sizes = [p['size'] for p in block]

            first_timestamp = min(timestamps)
            last_timestamp = max(timestamps)
            window_size = last_timestamp - first_timestamp

            num_frames = len(block)
            total_size = sum(sizes)

            inter_arrival_times = np.diff(sorted(timestamps))

            if mac not in mac_all_tp_count:
                mac_all_tp_count[mac] = 0
            mac_all_tp_count[mac] += num_frames

            feature = {
                'mac': mac,
                'type': tp,
                'subtype': subtype,
                'First(mac,tp)': first_timestamp,
                'Last(mac,tp)': last_timestamp,
                'W(mac,tp)': window_size,
                'C(mac,tp)': num_frames,
                'S(mac,tp)': sum(1 for p in block if p['src_mac'] == mac),
                'R(mac,tp)': sum(1 for p in block if p['dst_mac'] == mac),
                'len(mac,tp)': sizes,
                'gaps(mac,tp)': inter_arrival_times
            }
            features.append(feature)

    # 计算处理过的特征
    processed_features = []
    for feature in features:
        mac, tp, subtype = feature['mac'], feature['type'], feature['subtype']
        num_frames = feature['C(mac,tp)']
        window_size = feature['W(mac,tp)']
        total_size = feature['len(mac,tp)']
        inter_arrival_times = feature['gaps(mac,tp)']
        inter_arrival_times = np.array(inter_arrival_times).astype(float)
        all_mac_tp = all_mac_tp_count
        mac_all_tp = mac_all_tp_count[mac]

        rate = num_frames / window_size if window_size > 0 else 0
        fa = num_frames / all_mac_tp if all_mac_tp > 0 else 0
        fi = num_frames / mac_all_tp if mac_all_tp > 0 else 0
        rs = feature['S(mac,tp)'] / num_frames if num_frames > 0 else 0
        rr = feature['R(mac,tp)'] / num_frames if num_frames > 0 else 0
        sm = np.mean(total_size)
        sd = np.std(total_size)
        dm = np.mean(inter_arrival_times) if len(inter_arrival_times) > 0 else 0  # 计算增量dm
        dd = np.std(inter_arrival_times) if len(inter_arrival_times) > 0 else 0  # 计算增量dd

        processed_feature = {
            'mac': mac,
            'type': tp,
            'subtype': subtype,
            'rate': rate,
            'fa': fa,
            'fi': fi,
            'rs': rs,
            'rr': rr,
            'sm': sm,
            'sd': sd,
            'dm': dm,
            'dd': dd
        }
        processed_features.append(processed_feature)

    return processed_features


def prepare_training_data(processed_features, mac_labels):
    X = []
    y = []
    for feature in processed_features:
        mac = feature['mac']
        if mac in mac_labels:
            label = mac_labels[mac]
            X.append([
                feature['rate'],
                feature['fa'],
                feature['fi'],
                feature['rs'],
                feature['rr'],
                feature['sm'],
                feature['sd'],
                feature['dm'],
                feature['dd']
            ])
            y.append(label)
        else:
            label = 2
            X.append([
                feature['rate'],
                feature['fa'],
                feature['fi'],
                feature['rs'],
                feature['rr'],
                feature['sm'],
                feature['sd'],
                feature['dm'],
                feature['dd']
            ])
            y.append(label)
    return X, y


def read_all_pcap_files_to_packets(directory):
    packets = []

    # 获取目录中的所有 pcap 文件
    pcap_files = [f for f in os.listdir(directory) if f.endswith('.pcap')]

    # 遍历并读取每个 pcap 文件
    for pcap_file in pcap_files:
        file_path = os.path.join(directory, pcap_file)
        len1 = len(packets)
        packets.extend(rdpcap(file_path))
        print(f"Read {len(packets)-len1} packets from {pcap_file}")

    return packets


def calculate_mac_address_ratio(process_feature, mac_address):
    # 统计特定 MAC 地址在特征矩阵 X 中的占比
    total_samples = len(process_feature)  # 总样本数量
    mac_address_count = 0  # 特定 MAC 地址出现的次数

    # 遍历每个样本
    for feature in process_feature:
        # 检查特定 MAC 地址是否出现在样本中

        if feature['mac'] == mac_address:
            mac_address_count += 1

    # 计算特定 MAC 地址的占比
    # mac_address_ratio = mac_address_count / total_samples

    return mac_address_count


def data_process(pcap_file, block_size):
    directory = './data'

    packets = read_all_pcap_files_to_packets(directory)

    basic_features = [extract_basic_features(packet) for packet in packets if packet.haslayer(Dot11)]

    grouped_packets = group_by_mac_and_type(basic_features)

    processed_features = calculate_features(grouped_packets, block_size)

    X, y = prepare_training_data(processed_features, MAC_LABELS)
    # 统计标签为1的数据包比例
    total_packets = len(y)
    label_1_packets = sum(1 for val in y if val == 1)
    label_1_ratio = label_1_packets / total_packets if total_packets != 0 else 0
    print(f"Label 1 packets ratio: {label_1_ratio: .2f}")
    count = calculate_mac_address_ratio(processed_features, '34:7d:e4:5a:2b:b0')
    print(f"name packets ratio: {count: .2f}")
    for feature in processed_features:
        print(feature)

    return X, y
