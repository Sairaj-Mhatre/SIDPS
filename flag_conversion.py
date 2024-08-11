def get_flag_string(flags):
    flag_map = {
        '0x0002': 'S0',
        '0x0010': 'SF',
        '0x0014': 'REJ',
        '0x0018': 'RSTR',
        '0x0020': 'RSTO',
        '0x0024': 'RSTRH',
        '0x0000': 'OTH'
        # Add more mappings as necessary
    }
    return flag_map.get(flags, 'OTH')
