import pyshark
import dpkt
import pandas as pd
from collections import defaultdict
from protocols import deep_packet_inspection

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
            raw_packet = packet.get_raw_packet()
            service = deep_packet_inspection(raw_packet)
            
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
            sessions[connection]['service'] = service
            if packet.ip.src == src_ip:
                sessions[connection]['src_bytes'] += length
            if packet.ip.dst == dst_ip:
                sessions[connection]['dst_bytes'] += length
            
            if hasattr(packet, 'tcp'):
                sessions[connection]['flag'] = packet.tcp.flags
                sessions[connection]['urgent'] = int(packet.tcp.urgent_pointer)
            
            if hasattr(packet, 'ip'):
                sessions[connection]['wrong_fragment'] += int(packet.ip.frag_offset)
            
            # Update counts and rates here based on packet and session information
            sessions[connection]['count'] += 1
            if hasattr(packet, 'tcp'):
                if packet.tcp.flags_syn == '1' and packet.tcp.flags_ack == '0':
                    sessions[connection]['serror_count'] += 1
                    sessions[connection]['srv_serror_count'] += 1
                if packet.tcp.flags_rst == '1':
                    sessions[connection]['rerror_count'] += 1
                    sessions[connection]['srv_rerror_count'] += 1
            
            # Update destination host counts
            dst_host = (dst_ip, dst_port)
            sessions[dst_host]['dst_host_count'] += 1
            if protocol == sessions[dst_host]['protocol_type']:
                sessions[dst_host]['dst_host_srv_count'] += 1
                sessions[dst_host]['dst_host_same_srv_count'] += 1
            
            # Count same and different services
            if sessions[connection]['service'] == service:
                sessions[connection]['same_srv_count'] += 1
            else:
                sessions[connection]['diff_srv_count'] += 1

            if src_port == dst_port:
                sessions[connection]['dst_host_same_src_port_count'] += 1
            else:
                sessions[connection]['dst_host_srv_diff_host_count'] += 1

        except AttributeError:
            continue

    # Calculate duration and other rates
    for connection, features in sessions.items():
        features['duration'] = (features['end_time'] - features['start_time']).total_seconds()
        
        # Calculate various rates
        features['srv_count'] = sum(1 for k, v in sessions.items() if k[2:4] == connection[2:4])
        features['same_srv_count'] = sum(1 for k, v in sessions.items() if k[2:4] == connection[2:4] and v['service'] == features['service'])
        features['diff_srv_count'] = features['srv_count'] - features['same_srv_count']
        
        # Serror and Rerror rates
        if features['srv_count'] > 0:
            features['srv_serror_rate'] = features['srv_serror_count'] / features['srv_count']
            features['srv_rerror_rate'] = features['srv_rerror_count'] / features['srv_count']
        else:
            features['srv_serror_rate'] = 0
            features['srv_rerror_rate'] = 0

        if features['count'] > 0:
            features['serror_rate'] = features['serror_count'] / features['count']
            features['rerror_rate'] = features['rerror_count'] / features['count']
        else:
            features['serror_rate'] = 0
            features['rerror_rate'] = 0

        if features['dst_host_count'] > 0:
            features['dst_host_serror_rate'] = features['dst_host_serror_count'] / features['dst_host_count']
            features['dst_host_rerror_rate'] = features['dst_host_rerror_count'] / features['dst_host_count']
        else:
            features['dst_host_serror_rate'] = 0
            features['dst_host_rerror_rate'] = 0

    captured.close()
    return pd.DataFrame.from_dict(sessions, orient='index')
