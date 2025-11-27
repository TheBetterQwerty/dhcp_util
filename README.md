# DHCP Starvation Tool (C)

This is a lightweight DHCP starvation tool written in C. It is intended for research, penetration testing, and educational use in isolated or controlled environments. 

## Overview

DHCP starvation is a technique used to exhaust the IP address pool of a DHCP server by rapidly sending lease requests using spoofed MAC addresses. This can prevent legitimate devices from obtaining an IP address, effectively causing a denial-of-service (DoS) on the network.

This tool provides a simple and efficient way to simulate DHCP starvation attacks for testing the resilience of network infrastructure and security systems.

## Features (in progress)

- Written in C for performance and control
- Manual or automatic spoofing of MAC addresses
- Raw socket support for DHCP packet crafting
- Configurable interface and packet rate
- Minimal external dependencies

## Usage
'''
    [!] Usage: ./starver --packets <number>
'''

## Requirements

- C compiler (GCC/Clang)
- Root privileges (for raw socket access)
- Linux or UNIX-based system

## Disclaimer

This software is intended for **authorized security testing, research, and educational use only**. Unauthorized or malicious use on networks you do not own or have explicit permission to test is strictly prohibited and may be illegal.

The authors assume no responsibility for any damage caused by misuse of this tool.

