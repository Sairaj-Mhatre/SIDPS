# main.py
from capture import capture_packets
from feature_extraction import extract_features_from_pcap

def main():
    interface = 'your_interface'
    duration = 120  # Capture duration in seconds
    output_dir = r"F:\VIT\BE_Project\dev\Captures"
    
    pcap_file = capture_packets(interface, duration, output_dir)
    df = extract_features_from_pcap(pcap_file)
    
    csv_file = pcap_file.replace('.pcap', '.csv')
    df.to_csv(csv_file, index=False)
    print(f"Features extracted and saved to {csv_file}")
    print(df.head())

if __name__ == "__main__":
    main()
