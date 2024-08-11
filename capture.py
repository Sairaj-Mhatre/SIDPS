import pyshark
import os
from datetime import datetime

def capture_packets(interface, duration, output_dir):
    now = datetime.now()
    file_name = f"{now.strftime('%Y-%m-%d_%H-%M-%S')}.pcap"
    file_path = os.path.join(output_dir, file_name)
    
    os.makedirs(output_dir, exist_ok=True)
    print(f"Saving capture file to: {file_path}")

    try:
        capture = pyshark.LiveCapture(interface=interface, output_file=file_path)
        print("Starting capture...")
        capture.sniff(timeout=duration)
        print("Capture finished.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        capture.close()
    
    return file_path
