import os
import shutil
import subprocess
from datetime import datetime

# Function to capture packets using tshark
def capture_packets(interface="Ethernet", capture_duration=15, output_dir="F:/VIT/BE_Project/dev/pcap/input"):
    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create the pcap filename with a timestamp
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    pcap_file = os.path.join(output_dir, f"capture_{timestamp}.pcap")

    # Run tshark to capture packets for 15 seconds
    print(f"Starting packet capture for {capture_duration} seconds...")
    tshark_cmd = [
        "C:/Program Files/Wireshark/tshark.exe",  # Path to tshark.exe
        "-i", interface,                         # Interface to capture from
        "-a", f"duration:{capture_duration}",    # Capture duration in seconds
        "-w", pcap_file                          # Output file path
    ]
    
    subprocess.run(tshark_cmd)
    print(f"Packet capture completed: {pcap_file}")
    return pcap_file

# Function to reorder the PCAP file using editcap
def reorder_pcap(pcap_file):
    # Create a new reordered pcap filename
    reordered_pcap_file = pcap_file.replace(".pcap", "_reordered.pcap")
    editcap_cmd = [
        "C:/Program Files/Wireshark/editcap.exe",  # Path to editcap.exe
        pcap_file,                                  # Input file
        reordered_pcap_file                         # Output file
    ]
    
    print("Reordering PCAP file...")
    subprocess.run(editcap_cmd)
    print(f"Reordered PCAP file created: {reordered_pcap_file}")
    return reordered_pcap_file

# Function to convert pcap to csv using Docker
def run_docker_conversion(pcap_dir="F:/VIT/BE_Project/dev/pcap"):
    print("Starting PCAP to CSV conversion...")
    
    # Ensure input and output directories exist inside the Docker container
    input_dir = os.path.join(pcap_dir, "input")
    output_dir = os.path.join(pcap_dir, "output")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Docker command to run the conversion
    docker_cmd = [
        "docker", "run", 
        "-v", f"{pcap_dir}:/tmp/pcap", 
        "mielverkerken/cicflowmeter", 
        "/tmp/pcap/input", 
        "/tmp/pcap/output"
    ]

    # Run the Docker container
    subprocess.run(docker_cmd)
    print(f"Conversion completed. Check {output_dir} for results.")

# Function to move processed PCAP files to the 'processed' directory
def move_processed_files(reordered_pcap_file):
    processed_dir = "F:/VIT/BE_Project/dev/pcap/processed"
    if not os.path.exists(processed_dir):
        os.makedirs(processed_dir)

    # Move the reordered PCAP file to the processed directory
    shutil.move(reordered_pcap_file, os.path.join(processed_dir, os.path.basename(reordered_pcap_file)))
    print(f"Moved processed file to: {processed_dir}")

# Function that runs the capture and conversion process
def automate_capture_and_conversion():
    # 1. Capture packets for 15 seconds
    pcap_file = capture_packets()

    # 2. Reorder the PCAP file
    reordered_pcap_file = reorder_pcap(pcap_file)

    # 3. Delete the original PCAP file
    os.remove(pcap_file)
    print(f"Deleted original PCAP file: {pcap_file}")

    # 4. Run Docker container to convert the reordered PCAP file to CSV
    run_docker_conversion()

    # 5. Move processed PCAP file to the 'processed' directory
    move_processed_files(reordered_pcap_file)

# Main function to control the process based on user input
def main():
    try:
        while True:
            user_input = input("Enter 'start' to begin capturing or 'stop' to quit: ").strip().lower()

            if user_input == 'start':
                print("Starting capture and conversion process. Press Ctrl+C to stop.")
                
                # Continuously capture and convert packets until user interrupts or enters 'stop'
                while True:
                    automate_capture_and_conversion()
                    # No need to add a sleep, since the capture and conversion are sequential
                    # It will naturally pause between each iteration due to the capture and conversion times

            elif user_input == 'stop':
                print("Stopping the process...")
                break

            else:
                print("Invalid input. Please enter 'start' to capture or 'stop' to quit.")
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting...")
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the automation
if __name__ == "__main__":
    main()
