# PSProjects
This is a repository for powershell projects created by Through Technology Limited. Focussed around automation and service management.  Expect it to grow over time as we upload and create more scripts. Content will be subject to the MIT Open Source Initiative license.

Content:

1. Support Information Script (Tony Hawk,  2019) 

This script is designed to be deployed to Windows 10 client devices and executed by the user in the event that there is a major service incident or when performance and connectivity issues need to be escalated beyond 1st-line support.

The script will run checks of Win10/Defender configuration status,  proxy connectivity to BBC through any number of proxy IPs, file transfer speeds,  file share access,  logon server and numerous other useful troubleshooting steps. Results are written to a text file with a plain-english introduction,  which is subsequently uploaded to MS Teams  (we send it to an Incident Management team currently).   If there is no network connectivity,   then the user can always read key test results over the phone.

This uploaded version has been redacted,   so you'll need to tweak it to add addresses relevant to your organisation.
