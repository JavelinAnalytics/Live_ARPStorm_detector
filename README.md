# ARP Storm Detector

## Overview
The ARP Storm Detector is a Python-based network monitoring tool that performs live detection of ARP 
(Address Resolution Protocol) request storms on a selected network interface. The program captures ARP 
traffic using Scapy, calculates the ARP request rate, and identifies potential ARP storms when the request rate 
exceeds a configurable threshold. When a storm is detected, the tool provides a summary of observed network activity, 
including source MAC addresses and affected IP addresses. This project was developed as part of a cybersecurity and network 
monitoring learning exercise.

## How ARP Storm Detection Works
- The user selects a network interface.
- The program captures ARP traffic for a specified duration.
- The average ARP request rate is calculated.
- If the request rate exceeds the configured threshold, an ARP storm is declared.
- A summary of the event is displayed including source MAC addresses and IP addresses.

## Technologies Used
- Python 3
- Scapy

## Installation
```bash
pip install scapy
```

## Usage
Run the script:
```bash
python arp_detector.py
```
The program will display available network interfaces and prompt the user to select one for analysis.

## Configuration
The following values can be modified within the script:
-CAPTURE_SECONDS   the duration of packet capture
-THRESHOLD         ARP request/second required to declare a storm (default=20)

