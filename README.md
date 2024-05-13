# Network-Traffic-Analyzer-Tool


---

## Overview
This repository contains scripts for analyzing network traffic captured in a PCAP file. The scripts provide insights into various aspects of the network traffic, including protocol distribution, communication patterns between IP addresses, and detection of potential port scanning activities.

## Contents
1. **analyze_traffic.py**: This script reads a PCAP file, processes the captured packets, and provides an analysis of the network traffic.
   
2. **requirements.txt**: This file lists all the dependencies required to run the scripts. You can install them using `pip install -r requirements.txt`.

3. **README.md**: This markdown file contains instructions on how to use the scripts, along with an overview of the repository.

## Usage
To use the network traffic analyzer, follow these steps:

1. Clone the repository to your local machine.
2. Install the dependencies listed in `requirements.txt`.
3. Run the `sample.py` script with the path to the PCAP file as an argument. Optionally, you can specify a port scan threshold. For example:
4. The script will provide various analyses such as protocol distribution, IP communication patterns, latency, packet loss, throughput, and potential port scanning activities.

## Dependencies
- **Python**: The scripts are written in Python.
- **Scapy**: Scapy is used for reading and processing PCAP files.
- **Pandas**: Pandas is used for data manipulation and analysis.
- **Matplotlib**: Matplotlib is used for plotting graphs.
- **tqdm**: tqdm is used to display progress bars for processing packets.
- **tabulate**: tabulate is used for formatting tables in the output.

## Additional Notes
- Ensure that you have Python installed on your system.
- Make sure to provide the correct path to the PCAP file when running the script.
- Adjust the port scan threshold according to your requirements to detect potential port scanning activities.

---

Feel free to customize and enhance the scripts according to your specific needs. 

