import pyshark
import pandas as pd
from collections import defaultdict
from service_identification import identify_service
from flag_conversion import get_flag_string

def extract_features_from_pcap(pcap_file):
    captured = pyshark.FileCapture(pcap_file)
    
    sessions = defaultdict(lambda: {
        'src_bytes': 0,
        'dst_bytes': 0,
        'start_time': None,
        'end_time': None,
        'protocol_type': None,
        'service': None,
        'flag': None,
        'wrong_fragment': 0,
        'urgent': 0,
        'duration': 0,
        'count': 0,
        'serror_count': 0,
        'rerror_count': 0,
        'same_srv_count': 0,
        'diff_srv_count': 0,
        'srv_count': 0,
        'srv_serror_count': 0,
        'srv_rerror_count': 0,
        'dst_host_count': 0,
        'dst_host_srv_count': 0,
        'dst_host_same_srv_count': 0,
        'dst_host_diff_srv_count': 0,
        'dst_host_same_src_port_count': 0,
        'dst_host_srv_diff_host_count': 0,
        'dst_host_serror_count': 0,
        'dst_host_srv_serror_count': 0,
        'dst_host_rerror_count': 0,
        'dst_host_srv_rerror_count': 0
    })

    for packet in captured:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer
            src_port = int(packet[protocol].srcport)
            dst_port = int(packet[protocol].dstport)
            length = int(packet.length)
            time = packet.sniff_time
            connection = (src_ip, src_port, dst_ip, dst_port)
            
            if sessions[connection]['start_time'] is None:
                sessions[connection]['start_time'] = time
            sessions[connection]['end_time'] = time
            
            sessions[connection]['protocol_type'] = protocol
            sessions[connection]['service'] = identify_service(packet)
            if packet.ip.src == src_ip:
                sessions[connection]['src_bytes'] += length
            if packet.ip.dst == dst_ip:
                sessions[connection]['dst_bytes'] += length
            
            if hasattr(packet, 'tcp'):
                flag = packet.tcp.flags
                sessions[connection]['flag'] = get_flag_string(flag)
            
            sessions[connection]['count'] += 1
            if hasattr(packet, 'tcp'):
                if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                    sessions[connection]['serror_count'] += 1
                    sessions[connection]['srv_serror_count'] += 1
                if packet.tcp.flags_rst == '1':
                    sessions[connection]['rerror_count'] += 1
                    sessions[connection]['srv_rerror_count'] += 1
            
            dst_host = (dst_ip, dst_port)
            sessions[dst_host]['dst_host_count'] += 1
            if protocol == sessions[dst_host]['protocol_type']:
                sessions[dst_host]['dst_host_srv_count'] += 1
                sessions[dst_host]['dst_host_same_srv_count'] += 1
            
            if sessions[connection]['service'] == identify_service(packet):
                sessions[connection]['same_srv_count'] += 1
            else:
                sessions[connection]['diff_srv_count'] += 1

            if src_port == dst_port:
                sessions[connection]['dst_host_same_src_port_count'] += 1
            else:
                sessions[connection]['dst_host_srv_diff_host_count'] += 1

        except AttributeError:
            continue

    features = []
    for conn, data in sessions.items():
        if data['start_time'] and data['end_time']:
            data['duration'] = (data['end_time'] - data['start_time']).total_seconds()
        else:
            data['duration'] = 0  # or any other default value
        features.append(data)
    
    df = pd.DataFrame(features)
    return df
