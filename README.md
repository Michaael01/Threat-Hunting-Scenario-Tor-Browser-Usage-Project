![image](https://github.com/user-attachments/assets/9d7210d2-ffbc-4842-b103-19561eb42743)



# Threat-Hunting-Scenario-Tor-Browser-Usage-Project
- Scenario Creation

# Platforms and Languages Leveraged
 - Windows 10 Virtual Machines (Microsoft Azure)
 - EDR Platform: Microsoft Defender for Endpoint
 - Kusto Query Language (KQL)
 - Tor Browser

   
# Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

# High-Level TOR-Related IoC Discovery Plan
- Check DeviceFileEvents for any tor(.exe) or firefox(.exe) file events.
- Check DeviceProcessEvents for any signs of installation or usage.
- Check DeviceNetworkEvents for any signs of outgoing connections over known TOR ports.

# Steps Taken

## 1. Searched the DeviceFileEvents Table
Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called tor-shopping-list.txt on the desktop at 2024-11-08T22:27:19.7259964Z. These events began at 2024-11-08T22:14:48.6065231Z.

Query used to locate events:
