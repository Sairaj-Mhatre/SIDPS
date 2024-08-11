service_ports = {
    20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 67: 'dhcp', 68: 'dhcp',
    69: 'tftp', 79: 'finger', 80: 'http', 110: 'pop_3', 111: 'sunrpc', 119: 'nntp', 123: 'ntp_u', 135: 'loc_srv',
    137: 'netbios_ns', 138: 'netbios_dgm', 139: 'netbios_ssn', 143: 'imap4', 161: 'snmp', 162: 'snmp_trap',
    179: 'bgp', 194: 'irc', 220: 'imap3', 389: 'ldap', 443: 'http_443', 445: 'microsoft_ds', 512: 'exec',
    513: 'login', 514: 'shell', 515: 'printer', 520: 'efs', 530: 'courier', 540: 'uucp', 543: 'klogin',
    544: 'kshell', 546: 'dhcpv6_client', 547: 'dhcpv6_server', 554: 'rtsp', 631: 'ipp', 636: 'ldaps', 873: 'rsync',
    993: 'imap_ssl', 995: 'pop_ssl', 1080: 'socks', 1194: 'openvpn', 1433: 'ms_sql', 1434: 'ms_sql_monitor',
    1521: 'oracle', 2049: 'nfs', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6000: 'x11',
    6667: 'irc', 8080: 'http_proxy', 8443: 'https_alt', 9000: 'swserver', 10000: 'webmin', 20000: 'dnp',
    115: 'sftp', 411: 'directconnect', 412: 'directconnect', 636: 'ldaps', 873: 'rsync', 989: 'ftps_data', 990: 'ftps', 992: 'telnets', 993: 'imaps', 994: 'ircs', 995: 'pop3s', 1194: 'openvpn',
    # Add other ports and services as needed
}

protocol_services = {
    'ftp_data': 'ftp_data', 'ftp': 'ftp', 'ssh': 'ssh', 'telnet': 'telnet', 'smtp': 'smtp', 'domain': 'dns',
    'finger': 'finger', 'http': 'http', 'pop_3': 'pop', 'imap4': 'imap', 'nntp': 'nntp', 'ntp_u': 'ntp',
    'netbios_ns': 'nbns', 'netbios_dgm': 'nbdgm', 'netbios_ssn': 'nbtss', 'ldap': 'ldap', 'http_443': 'ssl',
    'exec': 'exec', 'login': 'rlogin', 'shell': 'rshell', 'printer': 'printer', 'efs': 'efs', 'courier': 'courier',
    'uucp': 'uucp', 'klogin': 'klogin', 'kshell': 'kshell', 'bgp': 'bgp', 'imap4': 'imap', 'systat': 'systat',
    'whois': 'whois', 'imap4': 'imap', 'iso_tsap': 'iso_tsap', 'sql_net': 'sql_net', 'time': 'time',
    'daytime': 'daytime', 'ssh': 'ssh', 'echo': 'echo', 'nntp': 'nntp', 'courier': 'courier', 'ntp_u': 'ntp',
    'pop_3': 'pop3', 'imap4': 'imap', 'http': 'http', 'smtp': 'smtp', 'auth': 'auth', 'pop_2': 'pop2',
    'printer': 'printer', 'netbios_ssn': 'nbtss', 'rje': 'rje', 'x11': 'x11'
    # Add other protocols as needed
}

def identify_service(packet):
    if hasattr(packet, 'tcp'):
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
        if src_port in service_ports:
            return service_ports[src_port]
        elif dst_port in service_ports:
            return service_ports[dst_port]
    
    if hasattr(packet, 'udp'):
        src_port = int(packet.udp.srcport)
        dst_port = int(packet.udp.dstport)
        if src_port in service_ports:
            return service_ports[src_port]
        elif dst_port in service_ports:
            return service_ports[dst_port]
    
    for proto in protocol_services.values():
        if hasattr(packet, proto):
            return proto
    
    return 'other'
