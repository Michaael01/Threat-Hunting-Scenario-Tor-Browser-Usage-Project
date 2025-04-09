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
Searched for any file that had the string "tor" in it and discovered what looks like the user "oluwatosin" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called tor-shopping-list.txt on the desktop at 2025-04-09T03:50:33.2169118Z. These events began at 2025-04-09T03:30:48.6234216Z.


| Query used to locate events:                                                                                                                                        |
|--------------------------------------------------------------------------------------------------------------------------------------------------|
| DeviceFileEvents <br>\| where DeviceName == "michaelvm-range"<br>\| where InitiatingProcessAccountName == "oluwatosin"<br>\| where FileName contains "tor"<br>\| where Timestamp >= datetime(2025-04-09T03:30:48.6234216Z)<br>\| order by Timestamp desc<br>\| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

![image](https://github.com/user-attachments/assets/e2150f92-e3bf-4077-8378-6b7086549d5e)


# 2. Searched the DeviceProcessEvents Table
Searched for any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at 2025-04-09T03:31:21.4757639Z, an employee on the "threat-hunt-lab" device ran the file tor-browser-windows-x86_64-portable-14.0.1.exe from their Downloads folder, using a command that triggered a silent installation.

| Query used to locate events:                                                                                                                                        |
|--------------------------------------------------------------------------------------------------------------------------------------------------|
| DeviceProcessEvents <br>\| where DeviceName == "michaelvm-range"<br>\| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe" <br>\| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

![image](https://github.com/user-attachments/assets/d36226b7-86c0-4503-90d3-27595e2c4485)

# 3. Searched the DeviceProcessEvents Table for TOR Browser Execution
Searched for any indication that user "oluwatosin" actually opened the TOR browser. There was evidence that they did open it at 2025-04-09T03:31:21.4757639Z. There were several other instances of firefox.exe (TOR) as well as tor.exe spawned afterwards. There were several instances of firefox.exe(Tor) as well as tor.exe spawned afterwards.

| Query used to locate events:                                                                                                                                                                                                                      |
|--------------------------------------------------------------------------------------------------------------------------------------------------|
| DeviceProcessEvents <br>\| where DeviceName == "michaelvm-range"<br>\|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"<br>\| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine<br>\| order by Timestamp desc

![image](https://github.com/user-attachments/assets/6664b35c-d22d-4b9e-840f-90dc895b90e3)


# 4. Searched the DeviceNetworkEvents Table for TOR Network Connections
Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. On 2025-04-09T03:31:34.8208517Z, a successful connection was made from the device "michaelvm-range" by the user "oluwatosin." The connection was established with the remote IP address 51.77.71.247 on port 9001. The connection was made to the URL "https://www.lfv7.com" via the Tor browser executable located at "c:\users\oluwatosin\desktop\tor browser\browser\torbrowser\tor\tor.exe." There were a couple of other connections to sites over port 443.

| Query used to locate events:                                                                                                                                                                                                                      |
|--------------------------------------------------------------------------------------------------------------------------------------------------|
| DeviceProcessEvents <br>\| where DeviceName == "michaelvm-range"<br>\| where InitiatingProcessAccountName != "system"<br>\| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")<br>\| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")<br>\| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath<br>\| order by Timestamp desc

![image](https://github.com/user-attachments/assets/aff85980-923e-4690-a4f3-31e5c26cdd18)


# Chronological Event Timeline

# 1. File Download - TOR Installer
- Timestamp: 2025-04-09T03:30:48.6234216Z
- Event: The user "employee" downloaded a file named tor-browser-windows-x86_64-portable-14.0.1.exe to the Downloads folder.
- Action: File download detected.
- File Path: C:\Users\oluwatosin\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe

# 2. Process Execution - TOR Browser Installation
- Timestamp: 2025-04-09T03:30:48.6234216Z
- Event: The user "employee" executed the file tor-browser-windows-x86_64-portable-14.0.1.exe in silent mode, initiating a background installation of the TOR Browser.
- Action: Process creation detected.
- Command: tor-browser-windows-x86_64-portable-14.0.1.exe /S
- File Path: C:\Users\oluwatosin\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe

# 3. Process Execution - TOR Browser Launch
- Timestamp: 2025-04-09T03:31:21.4757639Z
- Event: User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as firefox.exe and tor.exe, were also created, indicating that the browser launched successfully.
- Action: Process creation of TOR browser-related executables detected.
- File Path: C:\Users\oluwatosin\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

# 4. Network Connection - TOR Network
- Timestamp: 2025-04-09T03:31:34.8208517Z
- Event: A network connection to IP 176.198.159.33 on port 9001 by user "employee" was established using tor.exe, confirming TOR browser network activity.
- Action: Connection success.
- Process: tor.exe
- File Path: c:\users\oluwatosin\desktop\tor browser\browser\torbrowser\tor\tor.exe

# 5. Additional Network Connections - TOR Browser Activity
- Timestamps:
  - 2025-04-09T03:31:34.8208517Z - Connected to 68.8.241.30 on port 9001.
  - 2025-04-09T03:31:55.7715612Z - Local connection to 127.0.0.1 on port 9150.
- Event: Additional TOR network connections were established, indicating ongoing activity by user "oluwatosin" through the TOR browser.
- Action: Multiple successful connections detected.

# 6. File Creation - TOR Shopping List
- Timestamp: 2025-04-09T03:50:33.2169118Z
- Event: The user "oluwatosin" created a file named tor-shopping-list.txt on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- Action: File creation detected.
- File Path: C:\Users\employee\Desktop\tor-shopping-list.txt

  ![image](https://github.com/user-attachments/assets/ed4686bf-9e22-406b-88f4-54742463f298)


# Summary

The user "oluwatosin" on the "michaelvm-range" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named tor-shopping-list.txt. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

# Response Taken

TOR usage was confirmed on the endpoint threat-hunt-lab by the user oluwatosin. The device was isolated, and the user's direct manager was notified.
