# Bases.sh

## **Overview**

**Bases.sh** is a comprehensive DFIR (Digital Forensics & Incident Response) Baseline Information Gathering Script designed to collect essential system data. It features both a terminal-based interactive menu and a Whiptail-based GUI, enabling users to easily navigate and perform various system checks.

## **Features**

- **System Metadata Collection:** Hostname, OS version, uptime, etc.
- **User Information:** Current users, last logins, environment variables.
- **Network Information:** Interfaces, routing tables, active connections, iptables rules.
- **Filesystem Information:** Mounted filesystems, disk usage.
- **Kernel & Sysctl Information:** Loaded kernel modules, sysctl configurations.
- **Logs Collection:** Archives essential logs for further analysis.
- **Interactive GUI:** User-friendly interface using Whiptail for easier navigation and operation.

## **Installation**

### **Prerequisites**

- **Operating System:** Linux-based distributions (e.g., Ubuntu, Debian)
- **Dependencies:**
  - `bash`
  - `whiptail`
  - `psmisc` (for `pstree`)
  - `jq` (optional, for JSON validation)
  - Other standard Unix utilities (`sed`, `awk`, `grep`, etc.)

### **Installing Dependencies**

bash
sudo apt-get update
sudo apt-get install -y whiptail psmisc jq

# ⚙️ System Baseline Tool

![Banner](path_to_your_banner_image.png) *(Optional: Add a screenshot of the tool)*

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Customization](#customization)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

## Overview

The **System Baseline Tool** is a powerful PowerShell-based GUI application designed to help system administrators and IT professionals gather, analyze, and report on various aspects of a Windows system's configuration and performance. This tool provides an interactive interface to view datasets such as operating system details, hardware information, installed software, services, hotfixes, and more. It also includes advanced features like dynamic filtering and grouping, compliance scoring, and report generation.

## Features

- **Interactive Data Selection:** Choose from a wide range of datasets including OS, Computer System, BIOS, CPU, Memory, Disk Drives, Logical Disks, Volumes, Network Adapters, Software, Hotfixes, Services, Processes, Startup Commands, Firewall Rules, and Environment Variables.
  
- **Dynamic Filtering:** Easily filter data based on any matching text to quickly find relevant information.

- **Animated Banner:** Enjoy a visually appealing animated gradient banner in light mode.

- **Dark Mode:** Toggle between light and dark themes to suit your preference.

- **Compliance Scoring:** Assess system compliance based on predefined rules to ensure adherence to organizational standards.

- **Report Generation:** Generate comprehensive HTML reports of the current system baseline, including applied filters, grouping settings, and compliance scores.

- **Performance Optimizations:** On-demand data retrieval and virtualization in the data grid for efficient performance even with large datasets.

## Requirements

- **Operating System:** Windows 10 or later
- **PowerShell Version:** PowerShell 5.1 or later
- **Permissions:** Administrative privileges may be required to access certain system information.

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/SystemBaselineTool.git
