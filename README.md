# Azure SOC / SIEM Security Lab

A hands-on lab demonstrating the deployment of a Security Operations Center (SOC) using Microsoft Sentinel (SIEM) and a honeypot virtual machine to ingest and analyze live cyber attacks.

## Lab Overview & Results
* **SIEM Platform:** Microsoft Sentinel
* **Log Ingestion:** Log Analytics Workspaces
* **Live Map Tracking:**


## Table of Contents
- [Architecture & Workflow]
- [Technologies & Azure Services]
- [Lab Setup Steps]
- [Attack Visualization]
- [Key KQL Queries Used]

## Architecture & Workflow

<img width="1376" height="768" alt="image" src="https://github.com/user-attachments/assets/21929adc-1af3-45c2-a32c-ea464c3fdbe6" />

  1. **Phase 1: Security Event Generation**
     * Create a resource group and virtual network for the virtual machine.
     * Public attack traffic targets the vulnerable Windows VM honeypot.
     * The operating system automatically captures unauthorized access attempts natively within the Windows Security Logs (such as Event ID 4625         for failed logons).

  3. **Phase 2: Log Centralization & Repository**
     * The **Log Analytics Workspace** acts as the central data repository.
     * Instead of utilizing custom local scripts, data collection rules natively forward the security log events directly from the Virtual               Machine into the workspace repository.

  4. **Phase 3: SIEM Connection & Threat Analytics**
     * **Microsoft Sentinel** is connected directly to the Log Analytics Workspace to turn the raw data repository into an active SIEM platform.
     * Sentinel uses Kusto Query Language (KQL) to parse the streaming security events, surface potential threats, and trigger security incidents        when threshold alerts are crossed.


## Technologies & Azure Services
* **Cloud Platform:** Microsoft Azure
* **SIEM:** Microsoft Sentinel
* **Logging:** Log Analytics Workspaces
* **Compute:** Windows 10/11 Virtual Machine (Honeypot)
* **UI:** Microsoft Defender workbook using KQL for IP mapping

<img width="1512" height="545" alt="Screenshot 2026-08-11 at 2 30 33 PM" src="https://github.com/user-attachments/assets/233eece9-98f7-433d-a6b1-060f0cf6decd" />


## Lab Setup Steps

### 1. VM Honeypot Deployment
* Create an Azure Resource Group and deploy a Windows Virtual Machine.
* Open all inbound ports in the Network Security Group (NSG) to make the VM discoverable to scanners.
* Turn off the Windows Defender Firewall inside the VM.

### 2. Log Ingestion & Enrichment
* Create a Log Analytics Workspace and connect it to your VM.
* Run the PowerShell log exporter script inside the VM to capture Event ID 4625.
* Set up a Custom Text Log (MMA or AMA) in Azure to ingest the script's output file.

<img width="1512" height="828" alt="Screenshot 2026-08-11 at 2 28 08 PM" src="https://github.com/user-attachments/assets/a03d0d3b-c823-477d-9c22-32948e204351" />


### 3. Sentinel SIEM Configuration
* Initialize Microsoft Sentinel on your Log Analytics Workspace.
* Build a custom Workbook using Kusto Query Language (KQL) to map out coordinates (`latitude_CF`, `longitude_CF`).

## Attack Simulation & Incident Response
* **The Attack:** Within hours of deployment, global bots began automated RDP brute-force attacks.
* **The Discovery:** Monitored massive spikes in failed login attempts via the Sentinel Overview dashboard.
* **The Analytics:** Created an Analytics Rule to automatically plot IP addresses on a map.

<img width="1512" height="683" alt="Screenshot 2026-08-11 at 2 20 43 PM" src="https://github.com/user-attachments/assets/0e945cd7-fa3f-4c17-a79d-8835facbd3aa" />



### RDP Geolocation Query
```text
SecurityEvent
| where EventID == 4625
| extend GeoIPInfo = geo_info_from_ip_address(IpAddress)
| extend country = tostring(GeoIPInfo.country),
         state = tostring(GeoIPInfo.state),
         city = tostring(GeoIPInfo.city),
         latitude = todouble(GeoIPInfo.latitude),
         longitude = todouble(GeoIPInfo.longitude)
| where isnotempty(latitude) and isnotempty(longitude)
| summarize count() by IpAddress, city, country, latitude, longitude
```


