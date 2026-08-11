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

  1. **Phase 1: Security Event Generation**
     * Public attack traffic targets the vulnerable Windows VM honeypot.
     * The operating system automatically captures unauthorized access attempts natively within the Windows Security Logs (such as Event ID 4625         for failed logons).

  2. **Phase 2: Log Centralization & Repository**
     * The **Log Analytics Workspace** acts as the central data repository.
     * Instead of utilizing custom local scripts, data collection rules natively forward the security log events directly from the Virtual               Machine into the workspace repository.

  3. **Phase 3: SIEM Connection & Threat Analytics**
     * **Microsoft Sentinel** is connected directly to the Log Analytics Workspace to turn the raw data repository into an active SIEM platform.
     * Sentinel uses Kusto Query Language (KQL) to parse the streaming security events, surface potential threats, and trigger security incidents        when threshold alerts are crossed.


## Technologies & Azure Services
* **Cloud Platform:** Microsoft Azure
* **SIEM:** Microsoft Sentinel
* **Logging:** Log Analytics Workspaces
* **Compute:** Windows 10/11 Virtual Machine (Honeypot)
* **UI:** Microsoft Defender workbook using KQL for IP mapping

## Lab Setup Steps

### 1. VM Honeypot Deployment
* Create an Azure Resource Group and deploy a Windows Virtual Machine.
* Open all inbound ports in the Network Security Group (NSG) to make the VM discoverable to scanners.
* Turn off the Windows Defender Firewall inside the VM.

### 2. Log Ingestion & Enrichment
* Create a Log Analytics Workspace and connect it to your VM.
* Run the PowerShell log exporter script inside the VM to capture Event ID 4625.
* Set up a Custom Text Log (MMA or AMA) in Azure to ingest the script's output file.

### 3. Sentinel SIEM Configuration
* Initialize Microsoft Sentinel on your Log Analytics Workspace.
* Build a custom Workbook using Kusto Query Language (KQL) to map out coordinates (`latitude_CF`, `longitude_CF`).

## Attack Simulation & Incident Response
* **The Attack:** Within hours of deployment, global bots began automated RDP brute-force attacks.
* **The Discovery:** Monitored massive spikes in failed login attempts via the Sentinel Overview dashboard.
* **The Analytics:** Created an Analytics Rule to automatically plot IP addresses on a map.

## Key KQL Queries Used

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


