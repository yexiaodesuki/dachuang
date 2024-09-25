import joblib
import scapy
from data_process import *


def prepare_training_data2(processed_features):
    X = []
    for feature in processed_features:
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
    return X


def predict(pcap_file,block_size):
    packets = rdpcap(pcap_file)

    basic_features = [extract_basic_features(packet) for packet in packets if packet.haslayer(Dot11)]

    grouped_packets = group_by_mac_and_type(basic_features)

    processed_features = calculate_features(grouped_packets, block_size)

    X = prepare_training_data2(processed_features)
    '''
    # 统计标签为1的数据包比例
    total_packets = len(y)
    label_1_packets = sum(1 for val in y if val == 1)
    label_1_ratio = label_1_packets / total_packets if total_packets != 0 else 0
    print(f"Label 1 packets ratio: {label_1_ratio: .2f}")
    count = calculate_mac_address_ratio(processed_features, '34:7d:e4:5a:2b:b0')
    print(f"name packets ratio: {count: .2f}")
        '''
    for feature in processed_features:
        print(feature)

    # 加载模型
    loaded_model = joblib.load('random_forest_model.pkl')

    # 使用加载的模型进行预测
    prediction = loaded_model.predict(X)
    if prediction == 1:
        # 输出预测结果
        print("预测结果:该设备为摄像头设备")
    elif prediction == 2:
        print("预测结果:该设备为其他设备")
