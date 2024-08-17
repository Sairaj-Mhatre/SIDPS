# protocols.py
import dpkt

# Add detection for additional protocols
def deep_packet_inspection(packet):
    try:
        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):
            # Check for TCP/UDP layer
            if isinstance(ip.data, dpkt.tcp.TCP):
                return identify_tcp_service(ip.data)
            elif isinstance(ip.data, dpkt.udp.UDP):
                return identify_udp_service(ip.data)
            # Additional Protocol Detection
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                return 'icmp'
            elif isinstance(ip.data, dpkt.igmp.IGMP):
                return 'igmp'
            # Add more protocols as needed

        elif isinstance(eth.data, dpkt.arp.ARP):
            return 'arp'
        elif isinstance(eth.data, dpkt.dns.DNS):
            return 'dns'
    except Exception as e:
        print(f"Failed to parse packet: {e}")
        return 'other'

    return 'other'

def identify_tcp_service(tcp_data):
    # Use well-known ports or deep inspection for TCP services
    service_ports = {
        20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain',
        67: 'dhcp', 68: 'dhcp', 69: 'tftp', 79: 'finger', 80: 'http', 110: 'pop_3',
        111: 'sunrpc', 119: 'nntp', 123: 'ntp_u', 135: 'loc_srv', 137: 'netbios_ns',
        138: 'netbios_dgm', 139: 'netbios_ssn', 143: 'imap4', 161: 'snmp', 162: 'snmp_trap',
        179: 'bgp', 194: 'irc', 220: 'imap3', 389: 'ldap', 443: 'http_443', 445: 'microsoft_ds',
        512: 'exec', 513: 'login', 514: 'shell', 515: 'printer', 520: 'efs', 530: 'courier',
        540: 'uucp', 543: 'klogin', 544: 'kshell', 546: 'dhcpv6_client', 547: 'dhcpv6_server',
        554: 'rtsp', 631: 'ipp', 636: 'ldaps', 873: 'rsync', 993: 'imap_ssl', 995: 'pop_ssl',
        1080: 'socks', 1194: 'openvpn', 1433: 'ms_sql', 1434: 'ms_sql_monitor', 1521: 'oracle',
        2049: 'nfs', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6000: 'x11',
        6667: 'irc', 8080: 'http_proxy', 8443: 'https_alt', 9000: 'swserver', 10000: 'webmin', 
        20000: 'dnp'
    }
    src_port = tcp_data.sport
    dst_port = tcp_data.dport
    return service_ports.get(src_port) or service_ports.get(dst_port) or 'other'

def identify_udp_service(udp_data):
    # Use well-known ports or deep inspection for UDP services
    service_ports = {
        53: 'dns', 67: 'dhcp', 68: 'dhcp', 69: 'tftp', 123: 'ntp',
        161: 'snmp', 162: 'snmp_trap', 500: 'isakmp', 514: 'syslog'
        # Add more UDP services as needed
    }
    src_port = udp_data.sport
    dst_port = udp_data.dport
    return service_ports.get(src_port) or service_ports.get(dst_port) or 'other'
