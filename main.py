import os
from capture import capture_packets
from feature_extraction import extract_features_from_pcap

def main():
    interface = 'Ethernet'  # Change to your network interface
    duration = 120  # Duration of capture in seconds
    base_dir = r"F:\VIT\Final Year Prj\dev\Captures"
    
    pcap_file = capture_packets(interface, duration, base_dir)
    csv_file = os.path.join(base_dir, f"{os.path.basename(pcap_file).replace('.pcap', '.csv')}")
    
    df = extract_features_from_pcap(pcap_file)
    df.to_csv(csv_file, index=False)
    
    print(f"Features extracted and saved to {csv_file}")
    print(df.head())

if __name__ == "__main__":
    main()
