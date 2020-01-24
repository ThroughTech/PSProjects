#  License

#  Copyright 2020 Through Technology Limited

#  Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), 
#  to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
#  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
#  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#  /License

#  Script / Environment Notes:

#  This script is designed to run on a restricted desktop where Powershell is configured without any additional modules and runs in Constrained Language Mode.
#  A number of commands do not work in this mode and as such, simpler options have had to be used.  This means that some sections are not as elegant as they could be, but all function
#  and will function on the most basic of PowerShell environments.

#  While a copy log file that is generated when run in complete mode is stored in the current logged on users 'Downloads' directory, the same file is copied to a Teams site.
#  Teams is a useful repository, however a standard SharePoint store can be used as well.  In order to utilise this function (Teams or SharePoint) the SharePoint Client Components
#  will need to be installed on the target device.

#  In addition, the script writes all info to an on prem SQL database, data retrieval however, is not part of this script and an interface is required to do so.

#  This script uses Teams, as such, when run, Office 365 credentials are required as the local Domain credentials are not acceptable to authenticate.

#####################################
#                                   #
# Client Support Information Script #
#                                   #
#####################################
#                                   #
# Produced by:  Through Technology  #
#                                   #
# Written by:   Tony Hawk           #
#                                   #
# V2.4.3                            #
#                                   #
# Last updated:  23/01/20           #
#                                   #
#####################################

###########################################################################################################
#                                                                                                         #
#  Change History                                                                                         #
#                                                                                                         #
###########################################################################################################
#                                                                                                         #
#  v2.4.2                                                                                                 #
#                                                                                                         #
#  Introduction of Change History                                                                         #
#  Update of DNS test to include Name administrator and serial number                                     #
#                                                                                                         #
#  v2.4.3                                                                                                 #
#                                                                                                         #
#  Addition of InfrastructureTesting option, grouping all Inf tests                                       #
#  Logon server now qualifies which site it is on                                                         #
#  GPO server                                                                                             #
#  Last time GPOs were applied                                                                            #
#  List of applied GPOs                                                                                   #
#  Computer and User OU                                                                                   #
#  NTP server                                                                                             #
#  Last NTP sync                                                                                          #
#  Internal DNS resolution of Office 365 Federation server (STS)                                          #
#  External DNS resolution of key domains                                                                 #
#      Office 365 Federation server (STS)                                                                 #
#      Email domains                                                                                      #
#  Checking of Vodafone externally facing DNS servers (Infoblox)                                          #
#  Testing of the proxy load balancer virtual IPs (VIPs) for connectivity on TCP port 8080                #
#  The individual proxy test now shows user readable names for each, rather than simply the IP addresses  #
#  Internal (on-prem) file copy test to ascertain internal network performance                            #
#  Group memberships                                                                                      #
#  Few minor typo's                                                                                       #
#  Minor formatting improvements                                                                          #
#                                                                                                         #
###########################################################################################################

# Command line options; the script can be run either as a whole, or as individual tests as needed
Param(
    [parameter(Mandatory=$false)]
    [alias("a")]
    [switch]$AllProxyTest = $false,
    [parameter(Mandatory=$false)]
    [alias("d")]
    [switch]$Defender = $false,
    [parameter(Mandatory=$false)]
    [alias("dc")]
    [switch]$DomainChecks = $false,
    [parameter(Mandatory=$false)]
    [alias("dns")]
    [switch]$DNSServiceCheck = $false,
    [parameter(Mandatory=$false)]
    [alias("e")]
    [switch]$EmailDomainCheck = $false,
    [parameter(Mandatory=$false)]
    [alias("ew")]
    [switch]$ExternalWebTest = $false,
    [parameter(Mandatory=$false)]
    [alias("f")]
    [switch]$FileWriteTest = $false,
    [parameter(Mandatory=$false)]
    [alias("g")]
    [switch]$GroupPolicyCheck = $false,
    [parameter(Mandatory=$false)]
    [alias("fs")]
    [switch]$FileShareTest = $false,
    [parameter(Mandatory=$false)]
    [alias("h")]
    [switch]$Hotfixes = $false,
    [parameter(Mandatory=$false)]
    [alias("inf")]
    [switch]$InfrastructureTesting = $false,
    [parameter(Mandatory=$false)]
    [alias("i")]
    [switch]$IPInfo = $false,
    [parameter(Mandatory=$false)]
    [alias("ip")]
    [string]$IndividualProxyTest,
    [parameter(Mandatory=$false)]
    [alias("iw")]
    [switch]$InternalWebTest = $false,
    [parameter(Mandatory=$false)]
    [alias("m")]
    [switch]$MachineInfo = $false,
    [parameter(Mandatory=$false)]
    [alias("n")]
    [switch]$NTP = $false,
    [parameter(Mandatory=$false)]
    [alias("p")]
    [switch]$DCPing = $false,
    [parameter(Mandatory=$false)]
    [alias("s")]
    [switch]$SCCMSVCTest = $false,
    [parameter(Mandatory=$false)]
    [alias("tr")]
    [switch]$DCTraceRoute = $false
)

$FileNameDateStamp = Get-Date -format "yyyy.MM.dd.HH.mm"


###############################################
#                                             #
#  The following variables are site specific  #
#                                             #
###############################################

# The log file is written to the logged on users downloads directory as it is a known area with write access
$LogFileName = "$env:userprofile\downloads\$env:computername.csi.$FileNameDateStamp.txt"

# The root OU is used for AD searches
$RootOU = "dc=domain,dc=name,dc=here"

# Some environments use external facing DNS at the edge of the network, usually utilised by the proxies etc.  
$ExtDNS1 = "10.10.10.1"
$ExtDNS2 = "10.10.10.2"

# Domain controllers are used to establish connectivity results, 4 are used here, 2 in each datacentre
$DomainController1InDC1 = "10.10.1.1"
$DomainController2InDC1 = "10.10.1.2"
$DomainController1InDC2 = "10.10.2.1"
$DomainController2InDC2 = "10.10.2.2"

# The same domain controllers are used for DNS checks, the FQDN is required
$DomainController1NameInDC1 = "DomainController1DC1"
$DomainController2NameInDC1 = "DomainController2DC1"
$DomainController1NameInDC2 = "DomainController1DC2"
$DomainController2NameInDC2 = "DomainController2DC2"

# The script checks each individual proxy, however, the load balanced VIP is also checked
$ProxyLoadBalanceIP = "10.10.3.1"

# If the site is using office 365 Federation, the STS server is checked both from an internal and external perspective
$STSServer = "sts.domain.name.here"

# This is the list of proxy IPs
$ProxyList = "10.10.4.1" , "10.10.4.2", "10.10.4.3", "10.10.4.4", "10.10.5.1", "10.10.5.2", "10.10.5.3", "10.10.5.4"

# This variable needs to contain a UNC that all users can write to
$FileShareFullPath = "\\nas.domain.name.here\share"

# SQL DB connection string for the database that will host the information generated 
$connectionString = "Server = 'csisvr\csi'; Database = 'csidb'; Integrated Security =SSPI;"

# This script uploads the log file to a MS Teams site, this variable contains the path for said site 
$SiteURL = "https://domaniname.sharepoint.com/sites/csi"

# This variable contains the folder path where the logs are to be held on the Teams site
$foldername = "general/csilogs"

# This variable contains the URL for an internal, on-prem site that all users are able to access
$InternalWebSite = "internalsite.domain.name.here"

# This array contains all email domains owned by the company, for which the MX records are checked  
$EmailDomains = "autodiscover.emailsite1.co.uk", "autodiscover.emailsite2.co.uk" ,"autodiscover.emailsite3.co.uk","autodiscover.emailsite4.co.uk","autodiscover.emailsite5.co.uk"

# These variables are used to translate the datacentre site code to the readable name
$DC1Code = "1234"
$DC1Name = "DC1"
$DC2Code = "5678"
$DC2Name = "DC2"

###################################
#                                 #
#  End of site specific variables #
#                                 #
###################################


# An optional command-line switch to run numerous individual tests, specific to the infrastructure elements, as opposed to the local machine queries
If ($InfrastructureTesting){
    $AllProxyTest = $True
    $DCPing = $True
    $DomainChecks = $True
    $DNSServiceCheck = $True
    $EmailDomainCheck = $True
    $ExternalWebTest = $True
    $FileWriteTest = $True
    $FileShareTest = $True
    $InternalWebTest = $True
}

$ErrorActionPreference = 'SilentlyContinue'

Clear-Variable -Name ErrorLog -ErrorAction SilentlyContinue

####################

# Script Functions #

####################

# Gather machine information: Logon server, BIOS Name, Windows version, Windows build number, Domain, PC model

Function GetMachineInfo {
    Clear-Variable -Name DomainName, PCModel, PCModelVersion, OSVersionInfo. disksize, diskspace -ErrorAction SilentlyContinue
    $error.clear()
    $ComputerInfo = get-computerinfo | ForEach-Object {$_.logonserver, $_.biosname, $_.windowsversion}
    $LogonServerName = $ComputerInfo[0]
    $BIOSVersion = $ComputerInfo[1]
    $WindowsReleaseVersion = $ComputerInfo[2]
    $ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem | ForEach-Object {$_.domain, $_.model}
    $DomainName = $ComputerInfo[0]
    $PCModel = $ComputerInfo[1] # This doesn't work on Lenovo machines, the name uses a model code, not the common name
    $PCModelVersion = Get-CimInstance -ClassName Win32_ComputerSystemproduct | select version | ForEach-Object {$_.version}
    if ($PCModelVersion -gt 1) {$PCModel = "$PCModel, $PCModelVersion"}
    $OSVersionInfo = [System.Environment]::OSVersion.Version

    $VolInfo = Get-Volume 
    if ($VolInfo.Count -gt 0) {
        $DiskInfo = @()
        foreach ($vol in $VolInfo){
            if ($vol.driveletter.length -eq 0){
                $VolLetter = "None"
            } else {
                $VolLetter = $vol.driveletter
            }
            $DiskSize = [math]::Round($vol.size / 1024 /1024 / 1024,2)
            $DiskSpace = [math]::Round($vol.SizeRemaining / 1024 / 1024 / 1024,2)
            $tmp = $VolLetter, $DiskSize, $DiskSpace
            $DiskInfo += , $tmp
            Clear-Variable tmp -ErrorAction SilentlyContinue
        }
    }
    Return $DomainName, $PCModel, $BIOSVersion, $OSVersionInfo, $WindowsReleaseVersion, $DiskInfo, $LogonServerName
}

# Checking recently added hotfixes
# This collates all reported installed Windows hotfixes, only Description, ID and Install date are required, but other information is avaialable

Function CheckInstalledHotfixes {
    Clear-Variable -name RecentHotfixes, HotfixInstallSummary -ErrorAction SilentlyContinue
    $Hotfixes = get-hotfix | ForEach-Object {$_.description, $_.hotfixid, $_.installedon}
    $Hotfixcount = ($hotfixes.Count / 3)
    if ($hotfixes.Count -gt 0) {
        $hf=0
        $HFCount = 0
        for (;$hf -le $Hotfixcount; $hf++){
            $HFLineItem = $Hotfixes[$HFCount],$Hotfixes[$HFCount+1],$Hotfixes[$HFCount+2]
            $RecentHotfixes += , $HFLineItem
            Clear-Variable -name HFLineItem -ErrorAction SilentlyContinue
            $HFCount = $HFCount +3    
        } 
        $HotfixInstallSummary = "Yes"
    } else {
        $HotfixInstallSummary = "No"
    }
    Return $RecentHotfixes, $HotfixInstallSummary
}

#Check SCCM client service status
Function CheckSCCMClientService ($SCCMServiceinfo){
    Clear-Variable -Name SCCMSVCStatus, SCCMSummary -ErrorAction SilentlyContinue
    $error.clear()
    $SCCMSVCStatus = get-service | where-object {$_.Name -eq "CcmExec"} | ForEach-Object {$_.status}
    if ($SCCMSVCStatus.length -eq 0) {
        $SCCMSummary = "No"
    } else {
        $SCCMSummary = "Yes"
        $SCCMClientVersion = Get-WmiObject -Namespace root\ccm -Class sms_client | ForEach-Object {$_.clientversion}
    }
    Return $SCCMSummary, $SCCMSVCStatus, $SCCMClientVersion
}

#Checking Defender Status
Function GetDefenderStatus {
    Clear-Variable -Name DefenderInfo, DefenderAVSummary, DefenderLastUpdate -ErrorAction SilentlyContinue
    $error.clear()
    $DefenderInfo = Get-MpComputerStatus | ForEach-Object {$_.AMProductVersion, $_.AMEngineVersion, $_.AMServiceEnabled, $_.AntispywareEnabled, $_.AntispywareSignatureLastUpdated, $_.AntispywareSignatureVersion, $_.AntivirusEnabled, $_.AntivirusSignatureLastUpdated, $_.AntivirusSignatureVersion, $_.NISEnabled, $_.NISEngineVersion, $_.NISSignatureLastUpdated, $_.NISSignatureVersion, $_.OnAccessProtectionEnabled, $_.RealTimeProtectionEnabled}
    Return $DefenderInfo
}

#Get IP Info
Function GetIPInfo {
    Clear-Variable AdapterIDs, x, AdapterListCount, AdapterList, Networks,InterfaceDescription,IPAddress,SubnetMask,DefaultGateway,DNSServer,PhysicalAddress,DHCPEnabled,DHCPServer,DHCPLeaseObtained,DHCPLeaseExpires,DNSDomain,ConnectionType,DCLocale,DNSSuffixSearchList,DNSSuffixCount, ipinfo -ErrorAction SilentlyContinue
    $AdapterIDs = Get-NetIPConfiguration -All | ForEach-Object {$_.NetAdapter.DeviceID, $_.netadapter.interfacedescription}
    $x=0
    $AdapterListCount = $AdapterIDs.count
    for (;$x -le $AdapterListCount;$x=$x+2){
        $tmp = $AdapterIDs[$x], $AdapterIDs[$x+1]
        $AdapterList += , $tmp
    }

    $AllIPInfo = @()
    $Networks = Get-WmiObject Win32_NetworkAdapterConfiguration | ? {$_.IPEnabled}

    $DCLocale = ""
    foreach ($Network in $Networks) {
        $InterfaceDescription = $Network.Description
        $IPAddress  = [string]$Network.IpAddress[0]
        $SubnetMask  = [string]$Network.IPSubnet[0]
        $DefaultGateway = [string]$Network.DefaultIPGateway
        $DNSServer  = $Network.DNSServerSearchOrder
        $PhysicalAddress  = [string]$Network.MACAddress
        $DHCPEnabled = $network.DHCPEnabled
        $DHCPServer  = [string]$Network.DHCPServer
        $os = Get-WmiObject –Class Win32_OperatingSystem
        $DHCPLeaseObtained = $os.ConvertToDateTime($Network.DHCPLeaseObtained)
        $DHCPLeaseExpires = $os.ConvertToDateTime($Network.DHCPLeaseExpires)
        $DNSDomain  = $Network.DNSDomainSuffixSearchOrder

        # The VPN being used is AnyConnect, this section, when it sees an adapter named 'AnyConnect' reads the IP address and ascertains which datacentre the client is connected to
        # This info can be very useful for diagnosis

        if ($InterfaceDescription -match "AnyConnect"){
            $ConnectionType = "RAS"

################################################################################################################
#  When using RAS, this section translates the known DHCP IP to the datacentre that hosts the security device  #
################################################################################################################

            $DCCheck = $IPAddress | select-string -pattern '10.20'
            if ($DCCheck.length -gt 0) {$DCLocale = "DC1"}
            $DCCheck = $IPAddress | select-string -pattern '10.30'
            if ($DCCheck.length -gt 0) {$DCLocale = "DC2"}

################################################################################################################
################################################################################################################

        } else {
            # If no VPN is detected, it is assumed the device is plugged in to the LAN and a lookup is performed against all known subnets (Taken from a export of the DHCP service, as clients cannot query the DHCP server directly)
            $ConnectionType = "LAN"
            if ($DHCPServer.Length -gt 0) {
                $DCLocale = IPLookup $IPAddress
            }
        }
        $x=0
        for (;$x -le $AdapterList.Count;$x++){
            if ($AdapterList[$x][1] -eq $InterfaceDescription){
                $IPClassIDInfo = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($AdapterList[$x][0])" -Name DhcpClassId).DhcpClassId
            }
        }
        $InterfaceInfo = $ConnectionType, $DCLocale, $DNSDomain, $InterfaceDescription, $PhysicalAddress, $DHCPEnabled, $DHCPServer, $DHCPLeaseObtained, $DHCPLeaseExpires, $IPAddress, $SubnetMask, $DefaultGateway, $DNSServer, $IPClassIDInfo
       $AllIPInfo += , $InterfaceInfo
        $InterfaceInfo = ""
       $AdapterCount = $AdapterList.Count
    }

    Return $AllIPInfo, $AdapterCount
}

#Testing connectivity; this function can perform an ICMP echo test, or a specific port ping, which is useful for DNS server testing etc.
Function PingTest ($DestSvrs, $Port){
    Clear-Variable -Name PingTestResults, DCPingResults, FailureCount, tmp -ErrorAction SilentlyContinue
    $Failurecount = 0    
    $error.clear()
    $DCPingResults = @()
    foreach ($Svr in $DestSvrs) {
        If ($Port.length -gt 0){
            $PingTestResults = Test-NetConnection $svr -Port $Port -InformationLevel Detailed -ErrorAction SilentlyContinue -WarningAction SilentlyContinue| ForEach-Object {$_.InterfaceDescription, $_.TCPTestSucceeded, $_.Computername}
            $tmp = $PingTestResults[0],$PingTestResults[1],$PingTestResults[2]
            if (-not $tmp[1]) {$Failurecount = $FailureCount + 1}
        } else {
            $PingTestResults = Test-NetConnection $svr -InformationLevel Detailed -ErrorAction SilentlyContinue -WarningAction SilentlyContinue| ForEach-Object {$_.ComputerName, $_.NameResolutionResults, $_.InterfaceDescription, $_.SourceAddress, $_.NetRoute, $_.PingSucceeded, $_.PingReplyDetails}
            $tmp = $PingTestResults[0],$PingTestResults[1],$PingTestResults[2],$PingTestResults[3].IPAddress,$PingTestResults[4].nexthop,$PingTestResults[5],$PingTestResults[6].RoundtripTime
            if (-not $tmp[5]) {$Failurecount = $FailureCount + 1}
        }
        $DCPingResults += , $tmp
    }
    Return $DCPingResults, $Failurecount
}

# Testing DNS resolution
# This function tests for A or MX records, using internal or external DNS; the configuration of this site means that the results differ for some domains and thus both need to be checked in some circumstances

Function DNSTest ($ConnectivityTestServers, $RecordType, $InExt, $ExtSvr) {
    Clear-Variable -Name FailureCount, DNSLog, destsvr, DNSTestResult, DNSTestSummary, DNSOutput -ErrorAction SilentlyContinue
    $error.clear()
    $FailureCount = 0
    $DNSLog = @()
    foreach ($destsvr in $ConnectivityTestServers) {
        Clear-Variable -Name DNSTestResult -ErrorAction SilentlyContinue
        $error.Clear()
        If ($RecordType -eq "A"){
            If ($InExt -eq "In"){
                $DNSTestResult = Resolve-DnsName $destsvr -Type A | foreach {$_.Name, $_.ipaddress}
                if ($DNSTestResult.count -gt 0){$DNSSOATestResult = Resolve-DnsName $destsvr -DnsOnly -NoHostsFile -Type SOA | foreach {$_.NameAdministrator, $_.SerialNumber}}
            } elseif ($InExt -eq "Ext"){
                If ($ExtSvr -eq "None"){
                    $DNSSOATestResult = "Could not contact InfoBlox"
                } else {
                    $DNSTestResult = Resolve-DnsName $destsvr -Server $ExtSvr | foreach {$_.Name, $_.ipaddress}
                    if ($DNSTestResult.count -gt 0){$DNSSOATestResult = Resolve-DnsName $destsvr -server $ExtSvr -DnsOnly -NoHostsFile -Type SOA | foreach {$_.NameAdministrator, $_.SerialNumber}}
                }
            }
            $DNSOutput = @()
            if ($DNSTestResult.count -eq 0) {
                $DNSOutput = $destsvr, "Unable to resolve host"
                $FailureCount = $failurecount + 1
                $DNSLog += , $DNSOutput
            } else {
                $y=0
                for (;$y -le $dnstestresult.count - 1;$y=$y+4) {
                    $tmp = $DNSTestResult[$y], $DNSTestResult[$y+1], $DNSSOATestResult[0], $DNSSOATestResult[1]
                    $DNSLog += , $tmp
                }
            }
        } ElseIf ($RecordType -eq "MX"){
            If ($InExt -eq "In"){
                $DNSTestResult = Resolve-DnsName $destsvr -Type MX | foreach {$_.Name, $_.NameHost}
            } elseif ($InExt -eq "Ext"){
                If ($ExtSvr -eq "None"){
                    $DNSSOATestResult = "Could not contact InfoBlox" # InfoBlox is used here for external resolution by the Proxy servers 
                } else {
                    $DNSTestResult = Resolve-DnsName $destsvr -Type MX | foreach {$_.Name, $_.NameHost}
                }
            }
            $DNSOutput = @()
            if ($DNSTestResult.count -eq 0) {
                $DNSOutput = $destsvr, "Unable to resolve host"
                $FailureCount = $failurecount + 1
                $DNSLog += , $DNSOutput
            } else {
                $y=0
                for (;$y -le $dnstestresult.count - 1;$y=$y+2) {
                    $tmp = $destsvr, $DNSTestResult[$y], $DNSTestResult[$y+1]
                    $DNSLog += , $tmp
                }
            }
        }
    }
    if ($FailureCount -gt 0) {
        $DNSTestSummary = "$failurecount server(s) could not be resolved"
    } else {
        $DNSTestSummary = "All servers successfully resolved"
    }
    Return $DNSLog, $DNSTestSummary
}

# Running TraceRoute tests internally and externally
Function TraceRouteTest {
    Clear-Variable -Name ConnectivityTestServers, TraceRouteLog, destsvr, TraceRouteTestResults, TraceRouteOutput -ErrorAction SilentlyContinue
    $error.clear()
    # To test basic connectivity, a traceroute is made to a domain controller in each of the datacentres

    $ConnectivityTestServers = $DomainController1NameInDC1, $DomainController1NameInDC2
    $TraceRouteOutput = @()
    foreach ($destsvr in $ConnectivityTestServers) {
        $TraceRouteTestResults = Test-NetConnection $destsvr -TraceRoute -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        $TraceRouteOutput += , $TraceRouteTestResults
    }
    Return $TraceRouteOutput
}

# Testing internal connection to an accessible, internally hosted web server on Port TCP80 and SSL on TCP443
Function InternalWebTest {
    Clear-Variable -Name IntWebRes, TempVar, InternalWebTestSummary, PortNum, InternalWebTestResults, TCPPing -ErrorAction SilentlyContinue
    $error.clear()
    $IntWebRes =@()
    foreach ($PortNum in 80,443) {
        Clear-Variable -Name InternalWebTestResults -ErrorAction SilentlyContinue
        $InternalWebTestResults = Test-NetConnection -port $portnum -ComputerName $InternalWebsite -WarningAction SilentlyContinue
        $IntWebRes += , $InternalWebTestResults
        If (-not $InternalWebTestResults.TcpTestSucceeded) {$TCPPing="F"}
    }
    if ($TCPPing -eq "F"){$InternalWebTestSummary = "Failed"} else {$InternalWebTestSummary = "Succeeded"}
    Return $IntWebRes, $InternalWebTestSummary
}

# Testing external connection to the internet, downloading a 10MB file and calculating the time taken to give Mbps

Function ExternalWebTest ($proxy_server) {
    Clear-Variable -Name WebClient, proxyserver, DateStamp, WebSpeedCheck, ExternalWebTestSummary,ExtWebChkErr -ErrorAction SilentlyContinue
    $error.clear()
    $WebClient = new-object System.Net.WebClient
    $WebClient.Headers.Add("user-agent", "PowerShell Script")
    $proxyserver = "http://" + $proxy_server + ":8080"
    $ProxyAddress = [System.Net.WebProxy]::GetDefaultProxy().Address
    [system.net.webrequest]::defaultwebproxy = New-Object system.net.webproxy($proxyserver)
    [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
    $DateStamp = Get-Date
    Invoke-WebRequest -uri "http://ipv4.download.thinkbroadband.com/10MB.zip" | Out-Null
    if ($error[0].Exception.length -eq 0) {
        $WebSpeedCheck = $((10/((Get-Date)-$datestamp).TotalSeconds)*8)
        $WebSpeedCheck = [math]::Round($WebSpeedCheck,2)
        $ExternalWebTestSummary = "Succeeded"
    } else {
        $ExtWebChkErr = $error[0].Exception
        $ExternalWebTestSummary = "Failed"
    }
    if (-not $ErrorInfo) {$ErrorInfo = "None"}
    Return $ExternalWebTestSummary, $ExtWebChkErr, $WebSpeedCheck
}

# In order to test internal LAN and WAN speeds, a file is copied from a known file storage location; this function creates the test fiel
function New-EmptyFile ($FilePath, $FileName, $Size){
    if (test-path $FilePath){
        $FullName = $FilePath + "\" + $FileName
        $file = [System.IO.File]::Create($FullPath)
        $file.SetLength($Size)
        $file.Close()
        $tmp = Get-Item $file.Name
        if ($tmp){
            $FileCreation = $true
        } else {
            $FileCreation = $false
            $FileCreationSummary = "Failed to write the test file"
        }
    } else {
        $FileCreation = $false
        $FileCreationSummary = "Failed to open the target folder"
    }
    Return $FileCreation, $FileCreationSummary
}

# Check access to the internet via individual proxies
# While the proxy farm is fronted with load balencers, each proxy has a virtual IP, allowing each one to be individually tested

Function TestIndividualProxies ($proxy_servers, $TargetServer) {
    Clear-Variable -Name IndividualProxyTestLog, proxy, ProxyServer, ProxyAddress, Webclient, content,tmp -ErrorAction SilentlyContinue
    $error.clear()
    $IndividualProxyTestLog = @()
    foreach ($proxy_server in $proxy_servers) {
        $WebClient = new-object System.Net.WebClient
        $proxyserver = "http://" + $proxy_server+ ":8080"
        $ProxyAddress = [System.Net.WebProxy]::GetDefaultProxy().Address
        [system.net.webrequest]::defaultwebproxy = New-Object system.net.webproxy($proxyserver)
        [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
        $content = $WebClient.DownloadString($TargetServer)
        if ($content.length -gt 0){
            $tmp = $Proxy_Server, "Successful"
            $IndividualProxyTestLog += , $tmp
        } else {
            $tmp = $Proxy_Server, "Failed"
            $IndividualProxyTestLog += , $tmp
        }
        clear-variable -name content -ErrorAction SilentlyContinue
    }
    Return $IndividualProxyTestLog
}

# Test connectivity to file shares on domain controllers in each of the datacentres
# This tests file access end to end, but also highlights any GPO download issues, should a NetLogon share not be available

Function FileShareTest {
    Clear-variable -name SMBServerList, SMBConnectionResults, SMBSVR, SMBCheck, SMBCheckResult, FailureCount -ErrorAction SilentlyContinue
    $error.Clear()
    $SMBServerList = $DomainController1NameInDC1, $DomainController1NameInDC2
    $SMBConnectionResults = @()
    foreach ($SMBSVR in $SMBServerList) {
        clear-variable -name SMBCheck -ErrorAction SilentlyContinue
        $error.clear()
        try {
            $SMBCheck = Get-ChildItem \\$smbsvr\netlogon -WarningAction SilentlyContinue -erroraction SilentlyContinue
                if ($SMBCheck.Length -gt 0) {
                    $SMBCheckResult = $SMBSVR, "Successful"
                } else {
                    $SMBCheckResult = $SMBSVR, "Failed"
                    $FailureCount= $FailureCount + 1
                }
            } catch {
                $SMBCheckResult = $SMBSVR, "Failed"
                $FailureCount= $FailureCount + 1
            }
        $SMBConnectionResults += , $SMBCheckResult
    }
    try {
        clear-variable -name SMBCheck -ErrorAction SilentlyContinue
        $error.Clear()

        $SMBCheck = Get-ChildItem $FileShareFullPath -WarningAction SilentlyContinue -erroraction SilentlyContinue
            if ($SMBCheck.Length -gt 0) {
                $SMBCheckResult = "FileServerName","Successful"
            } else {
                $SMBCheckResult = "FileServerName","Failed"
                $FailureCount= $FailureCount + 1
            }
        } catch {
                $SMBCheckResult = "FileServerName","Failed"
            $FailureCount= $FailureCount + 1
        }
    $SMBConnectionResults += , $SMBCheckResult
    if ($FailureCount -gt 0) {$FileShareTestSummary = "Failed"} else {$FileShareTestSummary = "Succeeded"}
    Return $SMBConnectionResults, $FileShareTestSummary
}

# Subnet mask conversion routine

Function Convert-RvNetInt64ToIpAddress() 
{ 
    Param 
    ([int64]$Int64)
    '{0}.{1}.{2}.{3}' -f ([math]::Truncate($Int64 / 16777216)).ToString(), 
        ([math]::Truncate(($Int64 % 16777216) / 65536)).ToString(), 
        ([math]::Truncate(($Int64 % 65536)/256)).ToString(), 
        ([math]::Truncate($Int64 % 256)).ToString() 
} 

# This is a list of known DHCP scopes and associated site names, for the IP lookup when the device is on the LAN
# Only x.x.x.0, 128 and 192 subnets are used on site, so identifying the specific site with a lookup is relatively easy

Function ProxyNameLookup ($ProxyIP) {

    Clear-Variable tmp -WarningAction SilentlyContinue
    $ProxyNameLookupTable = @{
        '10.172.60.57' = "DC1 Proxy 1"
        '10.172.60.58' = "DC1 Proxy 2"
        '10.172.60.59' = "DC1 Proxy 3"
        '10.172.60.60' = "DC1 Proxy 4"
        '10.172.60.61' = "DC1 Proxy 5"
        '10.172.60.62' = "DC1 Proxy 6"
        '10.172.60.63' = "DC1 Proxy 7"
        '10.172.60.64' = "DC1 Proxy 8"
        '10.172.60.65' = "DC1 Proxy 9"
        '10.171.60.57' = "DC2 Proxy 1"
        '10.171.60.58' = "DC2 Proxy 2"
        '10.171.60.59' = "DC2 Proxy 3"
        '10.171.60.60' = "DC2 Proxy 4"
        '10.171.60.61' = "DC2 Proxy 5"
        '10.171.60.62' = "DC2 Proxy 6"
        '10.171.60.63' = "DC2 Proxy 7"
        '10.171.60.64' = "DC2 Proxy 8"
        '10.171.60.65' = "DC2 Proxy 9"
    }
    $tmp = $ProxyNameLookupTable[$ProxyIP]
    Return $tmp
}


Function IPLookup ($IncomingIP) {

###  Export the DHCP scopes, and list them below, in the following format:  IP = Sitename
###  In order to search gthe ranges, each one needs to be included in ascending order

    $IPLookupTable = @{
        '192.168.0.0' = 'Unknown site Local WiFi'
        '192.168.1.0' = 'Unknown site Local WiFi'
        '192.168.2.0' = 'Unknown site Local WiFi'
        '192.168.3.0' = 'Unknown site Local WiFi'
        '192.168.4.0' = 'Unknown site Local WiFi'
        '192.168.5.0' = 'Unknown site Local WiFi'
        '192.168.6.0' = 'Unknown site Local WiFi'
        '192.168.7.0' = 'Unknown site Local WiFi'
        '192.168.8.0' = 'Unknown site Local WiFi'
        '192.168.9.0' = 'Unknown site Local WiFi'
        '192.168.10.0' = 'Unknown site Local WiFi'
        '192.168.11.0' = 'Unknown site Local WiFi'
        '192.168.12.0' = 'Unknown site Local WiFi'
        '192.168.13.0' = 'Unknown site Local WiFi'
        '192.168.14.0' = 'Unknown site Local WiFi'
        '192.168.15.0' = 'Unknown site Local WiFi'
        '192.168.16.0' = 'Unknown site Local WiFi'
        '192.168.17.0' = 'Unknown site Local WiFi'
        '192.168.18.0' = 'Unknown site Local WiFi'
        '192.168.19.0' = 'Unknown site Local WiFi'
        '192.168.20.0' = 'Unknown site Local WiFi'
        '192.168.21.0' = 'Unknown site Local WiFi'
        '192.168.22.0' = 'Unknown site Local WiFi'
        '192.168.23.0' = 'Unknown site Local WiFi'
        '192.168.24.0' = 'Unknown site Local WiFi'
        '192.168.25.0' = 'Unknown site Local WiFi'
        '192.168.26.0' = 'Unknown site Local WiFi'
        '192.168.27.0' = 'Unknown site Local WiFi'
        '192.168.28.0' = 'Unknown site Local WiFi'
        '192.168.29.0' = 'Unknown site Local WiFi'
        '192.168.30.0' = 'Unknown site Local WiFi'
        '192.168.31.0' = 'Unknown site Local WiFi'
        '192.168.32.0' = 'Unknown site Local WiFi'
        '192.168.33.0' = 'Unknown site Local WiFi'
        '192.168.34.0' = 'Unknown site Local WiFi'
        '192.168.35.0' = 'Unknown site Local WiFi'
        '192.168.36.0' = 'Unknown site Local WiFi'
        '192.168.37.0' = 'Unknown site Local WiFi'
        '192.168.38.0' = 'Unknown site Local WiFi'
        '192.168.39.0' = 'Unknown site Local WiFi'
        '192.168.40.0' = 'Unknown site Local WiFi'
        '192.168.41.0' = 'Unknown site Local WiFi'
        '192.168.42.0' = 'Unknown site Local WiFi'
        '192.168.43.0' = 'Unknown site Local WiFi'
        '192.168.44.0' = 'Unknown site Local WiFi'
        '192.168.45.0' = 'Unknown site Local WiFi'
        '192.168.46.0' = 'Unknown site Local WiFi'
        '192.168.47.0' = 'Unknown site Local WiFi'
        '192.168.48.0' = 'Unknown site Local WiFi'
        '192.168.49.0' = 'Unknown site Local WiFi'
        '192.168.50.0' = 'Unknown site Local WiFi'
        '192.168.51.0' = 'Unknown site Local WiFi'
        '192.168.52.0' = 'Unknown site Local WiFi'
        '192.168.53.0' = 'Unknown site Local WiFi'
        '192.168.54.0' = 'Unknown site Local WiFi'
        '192.168.55.0' = 'Unknown site Local WiFi'
        '192.168.56.0' = 'Unknown site Local WiFi'
        '192.168.57.0' = 'Unknown site Local WiFi'
        '192.168.58.0' = 'Unknown site Local WiFi'
        '192.168.59.0' = 'Unknown site Local WiFi'
        '192.168.60.0' = 'Unknown site Local WiFi'
        '192.168.61.0' = 'Unknown site Local WiFi'
        '192.168.62.0' = 'Unknown site Local WiFi'
        '192.168.63.0' = 'Unknown site Local WiFi'
        '192.168.64.0' = 'Unknown site Local WiFi'
        '192.168.65.0' = 'Unknown site Local WiFi'
        '192.168.66.0' = 'Unknown site Local WiFi'
        '192.168.67.0' = 'Unknown site Local WiFi'
        '192.168.68.0' = 'Unknown site Local WiFi'
        '192.168.69.0' = 'Unknown site Local WiFi'
        '192.168.70.0' = 'Unknown site Local WiFi'
        '192.168.71.0' = 'Unknown site Local WiFi'
        '192.168.72.0' = 'Unknown site Local WiFi'
        '192.168.73.0' = 'Unknown site Local WiFi'
        '192.168.74.0' = 'Unknown site Local WiFi'
        '192.168.75.0' = 'Unknown site Local WiFi'
        '192.168.76.0' = 'Unknown site Local WiFi'
        '192.168.77.0' = 'Unknown site Local WiFi'
        '192.168.78.0' = 'Unknown site Local WiFi'
        '192.168.79.0' = 'Unknown site Local WiFi'
        '192.168.80.0' = 'Unknown site Local WiFi'
        '192.168.81.0' = 'Unknown site Local WiFi'
        '192.168.82.0' = 'Unknown site Local WiFi'
        '192.168.83.0' = 'Unknown site Local WiFi'
        '192.168.84.0' = 'Unknown site Local WiFi'
        '192.168.85.0' = 'Unknown site Local WiFi'
        '192.168.86.0' = 'Unknown site Local WiFi'
        '192.168.87.0' = 'Unknown site Local WiFi'
        '192.168.88.0' = 'Unknown site Local WiFi'
        '192.168.89.0' = 'Unknown site Local WiFi'
        '192.168.90.0' = 'Unknown site Local WiFi'
        '192.168.91.0' = 'Unknown site Local WiFi'
        '192.168.92.0' = 'Unknown site Local WiFi'
        '192.168.93.0' = 'Unknown site Local WiFi'
        '192.168.94.0' = 'Unknown site Local WiFi'
        '192.168.95.0' = 'Unknown site Local WiFi'
        '192.168.96.0' = 'Unknown site Local WiFi'
        '192.168.97.0' = 'Unknown site Local WiFi'
        '192.168.98.0' = 'Unknown site Local WiFi'
        '192.168.99.0' = 'Unknown site Local WiFi'
        '192.168.100.0' = 'Unknown site Local WiFi'
        '192.168.101.0' = 'Unknown site Local WiFi'
        '192.168.102.0' = 'Unknown site Local WiFi'
        '192.168.103.0' = 'Unknown site Local WiFi'
        '192.168.104.0' = 'Unknown site Local WiFi'
        '192.168.105.0' = 'Unknown site Local WiFi'
        '192.168.106.0' = 'Unknown site Local WiFi'
        '192.168.107.0' = 'Unknown site Local WiFi'
        '192.168.108.0' = 'Unknown site Local WiFi'
        '192.168.109.0' = 'Unknown site Local WiFi'
        '192.168.110.0' = 'Unknown site Local WiFi'
        '192.168.111.0' = 'Unknown site Local WiFi'
        '192.168.112.0' = 'Unknown site Local WiFi'
        '192.168.113.0' = 'Unknown site Local WiFi'
        '192.168.114.0' = 'Unknown site Local WiFi'
        '192.168.115.0' = 'Unknown site Local WiFi'
        '192.168.116.0' = 'Unknown site Local WiFi'
        '192.168.117.0' = 'Unknown site Local WiFi'
        '192.168.118.0' = 'Unknown site Local WiFi'
        '192.168.119.0' = 'Unknown site Local WiFi'
        '192.168.120.0' = 'Unknown site Local WiFi'
        '192.168.121.0' = 'Unknown site Local WiFi'
        '192.168.122.0' = 'Unknown site Local WiFi'
        '192.168.123.0' = 'Unknown site Local WiFi'
        '192.168.124.0' = 'Unknown site Local WiFi'
        '192.168.125.0' = 'Unknown site Local WiFi'
        '192.168.126.0' = 'Unknown site Local WiFi'
        '192.168.127.0' = 'Unknown site Local WiFi'
        '192.168.128.0' = 'Unknown site Local WiFi'
        '192.168.129.0' = 'Unknown site Local WiFi'
        '192.168.130.0' = 'Unknown site Local WiFi'
        '192.168.131.0' = 'Unknown site Local WiFi'
        '192.168.132.0' = 'Unknown site Local WiFi'
        '192.168.133.0' = 'Unknown site Local WiFi'
        '192.168.134.0' = 'Unknown site Local WiFi'
        '192.168.135.0' = 'Unknown site Local WiFi'
        '192.168.136.0' = 'Unknown site Local WiFi'
        '192.168.137.0' = 'Unknown site Local WiFi'
        '192.168.138.0' = 'Unknown site Local WiFi'
        '192.168.139.0' = 'Unknown site Local WiFi'
        '192.168.140.0' = 'Unknown site Local WiFi'
        '192.168.141.0' = 'Unknown site Local WiFi'
        '192.168.142.0' = 'Unknown site Local WiFi'
        '192.168.143.0' = 'Unknown site Local WiFi'
        '192.168.144.0' = 'Unknown site Local WiFi'
        '192.168.145.0' = 'Unknown site Local WiFi'
        '192.168.146.0' = 'Unknown site Local WiFi'
        '192.168.147.0' = 'Unknown site Local WiFi'
        '192.168.148.0' = 'Unknown site Local WiFi'
        '192.168.149.0' = 'Unknown site Local WiFi'
        '192.168.150.0' = 'Unknown site Local WiFi'
        '192.168.151.0' = 'Unknown site Local WiFi'
        '192.168.152.0' = 'Unknown site Local WiFi'
        '192.168.153.0' = 'Unknown site Local WiFi'
        '192.168.154.0' = 'Unknown site Local WiFi'
        '192.168.155.0' = 'Unknown site Local WiFi'
        '192.168.156.0' = 'Unknown site Local WiFi'
        '192.168.157.0' = 'Unknown site Local WiFi'
        '192.168.158.0' = 'Unknown site Local WiFi'
        '192.168.159.0' = 'Unknown site Local WiFi'
        '192.168.160.0' = 'Unknown site Local WiFi'
        '192.168.161.0' = 'Unknown site Local WiFi'
        '192.168.162.0' = 'Unknown site Local WiFi'
        '192.168.163.0' = 'Unknown site Local WiFi'
        '192.168.164.0' = 'Unknown site Local WiFi'
        '192.168.165.0' = 'Unknown site Local WiFi'
        '192.168.166.0' = 'Unknown site Local WiFi'
        '192.168.167.0' = 'Unknown site Local WiFi'
        '192.168.168.0' = 'Unknown site Local WiFi'
        '192.168.169.0' = 'Unknown site Local WiFi'
        '192.168.170.0' = 'Unknown site Local WiFi'
        '192.168.171.0' = 'Unknown site Local WiFi'
        '192.168.172.0' = 'Unknown site Local WiFi'
        '192.168.173.0' = 'Unknown site Local WiFi'
        '192.168.174.0' = 'Unknown site Local WiFi'
        '192.168.175.0' = 'Unknown site Local WiFi'
        '192.168.176.0' = 'Unknown site Local WiFi'
        '192.168.177.0' = 'Unknown site Local WiFi'
        '192.168.178.0' = 'Unknown site Local WiFi'
        '192.168.179.0' = 'Unknown site Local WiFi'
        '192.168.180.0' = 'Unknown site Local WiFi'
        '192.168.181.0' = 'Unknown site Local WiFi'
        '192.168.182.0' = 'Unknown site Local WiFi'
        '192.168.183.0' = 'Unknown site Local WiFi'
        '192.168.184.0' = 'Unknown site Local WiFi'
        '192.168.185.0' = 'Unknown site Local WiFi'
        '192.168.186.0' = 'Unknown site Local WiFi'
        '192.168.187.0' = 'Unknown site Local WiFi'
        '192.168.188.0' = 'Unknown site Local WiFi'
        '192.168.189.0' = 'Unknown site Local WiFi'
        '192.168.190.0' = 'Unknown site Local WiFi'
        '192.168.191.0' = 'Unknown site Local WiFi'
        '192.168.192.0' = 'Unknown site Local WiFi'
        '192.168.193.0' = 'Unknown site Local WiFi'
        '192.168.194.0' = 'Unknown site Local WiFi'
        '192.168.195.0' = 'Unknown site Local WiFi'
        '192.168.196.0' = 'Unknown site Local WiFi'
        '192.168.197.0' = 'Unknown site Local WiFi'
        '192.168.198.0' = 'Unknown site Local WiFi'
        '192.168.199.0' = 'Unknown site Local WiFi'
        '192.168.200.0' = 'Unknown site Local WiFi'
        '192.168.201.0' = 'Unknown site Local WiFi'
        '192.168.202.0' = 'Unknown site Local WiFi'
        '192.168.203.0' = 'Unknown site Local WiFi'
        '192.168.204.0' = 'Unknown site Local WiFi'
        '192.168.205.0' = 'Unknown site Local WiFi'
        '192.168.206.0' = 'Unknown site Local WiFi'
        '192.168.207.0' = 'Unknown site Local WiFi'
        '192.168.208.0' = 'Unknown site Local WiFi'
        '192.168.209.0' = 'Unknown site Local WiFi'
        '192.168.210.0' = 'Unknown site Local WiFi'
        '192.168.211.0' = 'Unknown site Local WiFi'
        '192.168.212.0' = 'Unknown site Local WiFi'
        '192.168.213.0' = 'Unknown site Local WiFi'
        '192.168.214.0' = 'Unknown site Local WiFi'
        '192.168.215.0' = 'Unknown site Local WiFi'
        '192.168.216.0' = 'Unknown site Local WiFi'
        '192.168.217.0' = 'Unknown site Local WiFi'
        '192.168.218.0' = 'Unknown site Local WiFi'
        '192.168.219.0' = 'Unknown site Local WiFi'
        '192.168.220.0' = 'Unknown site Local WiFi'
        '192.168.221.0' = 'Unknown site Local WiFi'
        '192.168.222.0' = 'Unknown site Local WiFi'
        '192.168.223.0' = 'Unknown site Local WiFi'
        '192.168.224.0' = 'Unknown site Local WiFi'
        '192.168.225.0' = 'Unknown site Local WiFi'
        '192.168.226.0' = 'Unknown site Local WiFi'
        '192.168.227.0' = 'Unknown site Local WiFi'
        '192.168.228.0' = 'Unknown site Local WiFi'
        '192.168.229.0' = 'Unknown site Local WiFi'
        '192.168.230.0' = 'Unknown site Local WiFi'
        '192.168.231.0' = 'Unknown site Local WiFi'
        '192.168.232.0' = 'Unknown site Local WiFi'
        '192.168.233.0' = 'Unknown site Local WiFi'
        '192.168.234.0' = 'Unknown site Local WiFi'
        '192.168.235.0' = 'Unknown site Local WiFi'
        '192.168.236.0' = 'Unknown site Local WiFi'
        '192.168.237.0' = 'Unknown site Local WiFi'
        '192.168.238.0' = 'Unknown site Local WiFi'
        '192.168.239.0' = 'Unknown site Local WiFi'
        '192.168.240.0' = 'Unknown site Local WiFi'
        '192.168.241.0' = 'Unknown site Local WiFi'
        '192.168.242.0' = 'Unknown site Local WiFi'
        '192.168.243.0' = 'Unknown site Local WiFi'
        '192.168.244.0' = 'Unknown site Local WiFi'
        '192.168.245.0' = 'Unknown site Local WiFi'
        '192.168.246.0' = 'Unknown site Local WiFi'
        '192.168.247.0' = 'Unknown site Local WiFi'
        '192.168.248.0' = 'Unknown site Local WiFi'
        '192.168.249.0' = 'Unknown site Local WiFi'
        '192.168.250.0' = 'Unknown site Local WiFi'
        '192.168.251.0' = 'Unknown site Local WiFi'
        '192.168.252.0' = 'Unknown site Local WiFi'
        '192.168.253.0' = 'Unknown site Local WiFi'
        '192.168.254.0' = 'Unknown site Local WiFi'

        'x.x.x.0' = 'Site 1'
        'x.x.x.128' = 'Site 2'
        'x.x.x.192' = 'Site 3'

    }

    $SplitIP = $IncomingIP.Split(".")
    $tmpIP = [int]$SplitIP[3]
    if ($tmpip -lt 64){
        $tmpLookup = $SplitIP[0] + "." + $SplitIP[1]  + "." + $SplitIP[2] + ".0" 
        $tmp = $IPLookupTable[$tmplookup]
        if ($tmp.length -eq 0) {
            $tmp = "Could not find the DHCP Scope"
        }
    } elseif ($tmpip -lt 128){
        $tmpLookup = $SplitIP[0] + "." + $SplitIP[1]  + "." + $SplitIP[2] + ".128" 
        $tmp = $IPLookupTable[$tmplookup]
        if ($tmp.length -eq 0) {
            $tmpLookup = $SplitIP[0] + "." + $SplitIP[1]  + "." + $SplitIP[2] + ".0" 
            $tmp = $IPLookupTable[$tmplookup]
            if ($tmplookup.length -eq 0) {
                $tmp = "Could not find the DHCP Scope"
            }
        }
    } elseif ($tmpip -lt 255){
        $tmpLookup = $SplitIP[0] + "." + $SplitIP[1]  + "." + $SplitIP[2] + ".192" 
        $tmp = $IPLookupTable[$tmplookup]
        if ($tmp.length -eq 0) {
            $tmpLookup = $SplitIP[0] + "." + $SplitIP[1]  + "." + $SplitIP[2] + ".128" 
            $tmp = $IPLookupTable[$tmplookup]
            if ($tmp.length -eq 0) {
                $tmpLookup = $SplitIP[0] + "." + $SplitIP[1]  + "." + $SplitIP[2] + ".0" 
                $tmp = $IPLookupTable[$tmplookup]
                if ($tmplookup.length -eq 0) {
                    $tmp = "Could not find the DHCP Scope"
                }
            }
        }
    }
    return $tmp
}

#####################

# Independent Tests #

#####################

# All individual tests are designed to output to the console, no results are saved; as such they are fomatted accordingly, to be easily readable

# This test connects to 'bbc.co.uk' through each individual proxy (VIP) to establish if connectivity is achieveable.
# All proxy VIPs are tested, to ensure the F5 is not the connectivity issue

if ($AllProxyTest) {
    write-host "`r`nTesting connectivity to all F5 VIPs on port 8080`r`n"
    Clear-Variable ICMPTest, PingResults, FailureSummary, x, tmp1, tmp2 -ErrorAction SilentlyContinue
    $ICMPTest = PingTest $ProxyList 8080
    $PingResults = $ICMPTest[0]
    $FailureSummary = $ICMPTest[1]
    If ($FailureSummary -gt 0) {
        Write-Host "$FailureSummary F5 VIP(s) could not be contacted`r`n"
    } else {
        Write-Host "All F5 VIPs were successfully contacted on port 8080`r`n"
    }
    $x = 0
    Clear-Variable ExtSvr -ErrorAction SilentlyContinue
    "{0,-40} {1,-40}" -f  "Destination VIP", "TCP Ping (8080) Result`r`n"
    for (;$x -le $PingResults.count -1;$x++){
        $PxyIP = $PingResults[$x][2]
        $ProxyName = ProxyNameLookup $PxyIP
        If ($PingResults[$x][0]){$ExtSvr = $PingResults[$x][2]}
        $tmp1 = $PingResults[$x][1]
        $tmp2 = $PingResults[$x][2] + " (" + $ProxyName + ")"
        "{0,-40} {1,-40}" -f  $tmp2, $tmp1
        Clear-Variable tmp1, tmp2, ProxyName -ErrorAction SilentlyContinue
    }

    write-host "`r`nTesting basic connectivity to all proxies in both datacentres`r`n"
    Clear-Variable -name Proxytestlog -ErrorAction SilentlyContinue
    $Proxytestlog = TestIndividualProxies $ProxyList "http://bbc.co.uk"
    $x=0
    "{0,-40} {1,-40}" -f  "Proxy", "Connection Result`r`n"

    For (;$x -le $Proxytestlog.count -1;$x++){
        $PxyIP = $Proxytestlog[$x][0]
        $ProxyName = ProxyNameLookup $PxyIP
        $tmp1 = $ProxyName + " (" + $Proxytestlog[$x][0] + ")"
        $tmp2 = $Proxytestlog[$x][1]
        "{0,-40} {1,-40}" -f  $tmp1, $tmp2
    }
    Write-Host "`r`n"
}

# This test downloads a 10MB file and times it, providing a Mbps output

if ($IndividualProxyTest) {
    Write-Host "`r`nDownloading a 10MB test file from the Internet to check connectivity and bandwidth via $IndividualProxyTest `r`n"
    Clear-Variable -Name ExternalWebTesting, ExtWebChkErr, ExternalWebTestLog, tmp -ErrorAction SilentlyContinue
    $ExternalWebTesting = ExternalWebTest $IndividualProxyTest
    $ExtWebChkErr = $ExternalWebTesting[1]
    $WebSpeedCheck = $ExternalWebTesting[2]

    if ($ExtWebChkErr.length -gt 0) {
        $tmp = [string]$ExtWebChkErr.message
        Write-Host "Failed to download the test file:  " $tmp
    } else {
        Write-Host "Download of a 10MB file produced a speed result of: $WebSpeedCheck Mbps`r`n"
    }
}

# This test checks for all known email domains, to ensure the DNS information is correct

If ($EmailDomainCheck){
    Clear-Variable ICMPTest, PingResults, ExtSvr -ErrorAction SilentlyContinue
    # Tests to ensure connectivity to an external DNS server and falls back to a second is the first is not available
    $ICMPTest = PingTest $ExtDNS1 53
    $PingResults = $ICMPTest[0]
    if ($PingResults[0][1]){
        $ExtSvr = $ExtDNS1
    } else {
        $ICMPTest = PingTest $ExtDNS2 53
        $PingResults = $ICMPTest[0]
        if ($PingResults[0][1]){
            $ExtSvr = $ExtDNS2
        } else {
            $ExtSvr = "None"
        }
    }

    If ($ExtSvr -notlike "None"){
        Clear-Variable -Name DNSInfo, DNSLog, DNSExtTestSummary, ConnectivityTestServers, DNSExtResLog -ErrorAction SilentlyContinue
        $ConnectivityTestServers = $EmailDomains
        $DNSInfo = DNSTest $ConnectivityTestServers MX In
        $DNSExtLog = $DNSInfo[0]
        $DNSExtTestSummary = $DNSInfo[1]
        $x=0
        $tmp = ""
        $tmpCount = 0
        $DisplayTmp = @()
        for (;$x -le $DNSExtLog.count - 1;$x++) {
            If ($tmp -notlike $DNSExtLog[$x][0]){
                If ($tmpCount -gt 0){
                    Write-Host "`r`n"
                    Write-Host $DNSExtLog[$x-1][0] "`r`n"
                    "{0,-40} {1,-40}" -f  "Record Name", "Destination`r`n"
                    if ($DisplayTmp.count -gt 0){
                        $y = 0
                        for (;$y -le $DisplayTmp.count -2 ;$y++){
                            "{0,-40} {1,-40}" -f $Displaytmp[$y][0], $DisplayTmp[$y][1]
                        }
                    }
                    $DisplayTmp = @()
                }
                $tmp = $DNSExtLog[$x][0]
                $dtmp = $DNSExtLog[$x][1], $DNSExtLog[$x][2]
                $DisplayTmp  += , $dtmp
            } else {
                $dtmp = $DNSExtLog[$x][1], $DNSExtLog[$x][2]
                $DisplayTmp  += , $dtmp
            }
            $tmpCount = $tmpCount +1
        }

        $tmp = "`n" + $DNSExtLog[$DNSExtLog.count-1][0] + "`r`n"
        Write-Host "`n" $tmp
        "{0,-40} {1,-40}" -f  "Record Name", "Destination`r`n"
        $y = 0
        if ($DisplayTmp.count -gt 0){
            for (;$y -le $DisplayTmp.count -2 ;$y++){
                "{0,-40} {1,-40}" -f $Displaytmp[$y][0], $DisplayTmp[$y][1]
            }
            Write-Host "`r`n"
        }
    } else {
        "{0,-30} {1,-30}  {3,-30}" -f  "Originating Domain", "Record Name", "Destination`r`n"
        "{0,-30}" -f "Unable to connect to either of the external DNS servers"
    }
}

# This tests web access speed via the load balancer

if ($ExternalWebTest) {
    Write-Host "`r`nDownloading a 10MB test file from the Internet to check connectivity and bandwidth via WebAccessA `r`n"
    Clear-Variable -Name ExternalWebTesting, ExtWebChkErr, ExternalWebTestLog, tmp -ErrorAction SilentlyContinue
    $ExternalWebTesting = ExternalWebTest $ProxyLoadBalanceIP
    $ExtWebChkErr = $ExternalWebTesting[1]
    $WebSpeedCheck = $ExternalWebTesting[2]

    if ($ExtWebChkErr.length -gt 0) {
        $tmp = [string]$ExtWebChkErr.message
        Write-Host "Failed to download the test file:  " $tmp
    } else {
        Write-Host "Download of a 10MB file produced a speed result of: $WebSpeedCheck Mbps`r`n"
    }
}

# This will display the Microsoft Defender AV information

If ($Defender) {
    Clear-Variable -Name DefenderInfo -ErrorAction SilentlyContinue
    $DefenderInfo = GetDefenderStatus
    
    if ($DefenderInfo.Length -gt 0){
        Write-Host "`r`nDefender status`r`n"
        "{0,-70} {1,-70}" -f "Anti-Malware Product Version", $DefenderInfo[0]
        "{0,-70} {1,-70}" -f "Anti-Malware Engine Version", $DefenderInfo[1]
        "{0,-70} {1,-70}" -f "Anti-Malware Service Enabled", $DefenderInfo[2]
        "{0,-70} {1,-70}" -f "Anti-spyware Enabled", $DefenderInfo[3]
        "{0,-70} {1,-70}" -f "Anti-spyware Signature Last Updated", $DefenderInfo[4]
        "{0,-70} {1,-70}" -f "Anti-spyware Signature Version", $DefenderInfo[5]
        "{0,-70} {1,-70}" -f "Anti-virus Enabled", $DefenderInfo[6]
        "{0,-70} {1,-70}" -f "Anti-virus Signature Last Updated", $DefenderInfo[7]
        "{0,-70} {1,-70}" -f "Anti-virus Signature Version", $DefenderInfo[8]
        "{0,-70} {1,-70}" -f "Network Realtime Inspection Service Enabled", $DefenderInfo[9]
        "{0,-70} {1,-70}" -f "Network Realtime Inspection Service Engine Version", $DefenderInfo[10]
        "{0,-70} {1,-70}" -f "Network Realtime Inspection Service Signature Last Updated", $DefenderInfo[11]
        "{0,-70} {1,-70}" -f "Network Realtime Inspection Service Signature Version", $DefenderInfo[12]
        "{0,-70} {1,-70}" -f "On Access Protection Enabled", $DefenderInfo[13]
        "{0,-70} {1,-70}" -f "Real Time Protection Enabled",$DefenderInfo[14]
    }
}

# Running DCDiag and RepAdmin to gather detailed domain health information
# This information is recorded and Notepad is launched when complete

if ($DomainChecks) {
    # 4 domain controllers are checked, 2 in each datacentre to get a good spread of domain and replication information 

    $svrs = $DomainController1InDC1, $DomainController2InDC1, $DomainController1InDC2, $DomainController2InDC2
    Foreach ($DCIP in $Svrs) {
        $FailureCount = 0
        $ICMPTest = PingTest $DCIP
        $FailureCount = $ICMPTest[1]
        if ($FailureCount -eq 0) {
            $TargetDC = $DCIP
        } else {
            $DCFAilureCount =  $DCFAilureCount + 1 
        }
    }

    $datestamp = Get-Date -format "yyyy.MM.dd.HH.mm"
    $DomainLogFileName = "$env:userprofile\downloads\$env:computername.domaincheck.$datestamp.txt"
    Write-host "Checking domain health"
    $DCDiagResults = dcdiag /v /c /d /s:$targetDC
    $DCDiagResults = $DCDiagResults | Out-String
    $DCDiagResults = $DCDiagResults.trim()
    $RepAdminResults = repadmin /showrepl /all /verbose
    $RepAdminResults2 = repadmin /replsummary
    $RepAdminResults = $RepAdminResults + "`r`n`r`n" + $RepAdminResults2
    $RepAdminResults = $RepAdminResults | Out-String
    $RepAdminResults = $RepAdminResults.trim()
    write-output "Domain Check Log File" | out-file $DomainLogFileName
    $DomainLogTest = @"

$Datestamp

--------------------------
- Checking Domain Health -
--------------------------

$DCDiagResults

--------------------------------------
- Checking Domain Replication Health -
--------------------------------------

$RepAdminResults

"@

    Add-Content $DomainLogFileName $Domainlogtest
    Start-Process "c:\windows\system32\notepad.exe" $DomainLogFileName
}

# This test writes a 50MB file to a repository in the datacentre; the time taken is measured and Mbps calculated.  All users require access to this file share with write access.

If ($FileWriteTest) {

    Write-Host "Testing file system connectivity speed, writing a 50MB file to storage in the datacentre`r`n"
    Clear-Variable Datestamp, FileSpeedCheck, FileWriteTestSummary -ErrorAction SilentlyContinue
    $error.Clear()
    Clear-Variable tmp, x -ErrorAction SilentlyContinue
    $x=0
    for (;$x -le 100; $x++){
        $tmp = $tmp + "xxxxxxxx"
    }
    $x=0
    for (;$x -le 14; $x++){
        $tmp = $tmp + $tmp
    }
    $FileName = $env:computername + "-CSIFileWriteTest.txt"
    $FullPath = $env:userprofile + "\" + $FileName

    $DestinationPath = $FileShareFullPath
    $DestinationFullPath = $FileShareFullPath + "\" + $FileName
    write-output $tmp | out-file $FullPath
    if (Test-Path $FileShareFullPath){
        $DateStamp = Get-Date
        $CopyTmp = Copy-Item $FullPath -Destination $DestinationPath -PassThru -ErrorAction SilentlyContinue
        If ($CopyTmp){
            $FileSpeedCheck = $((10/((Get-Date)-$datestamp).TotalSeconds)*8)
            $FileSpeedCheck = [math]::Round($FileSpeedCheck,2)
            $FileSpeedCheck = [string]$FileSpeedCheck + "mbps"
            Write-Host "File creation successful, at an average of" $FileSpeedCheck "`r`n"
            Remove-Item –path $DestinationFullPath
            Remove-Item –path $FullPath
        } else {
            Write-Host "Unable to open the target folder`r`n"
        }
    } else {
        Write-Host "Failed to create the test file, error:`r`n"
        Write-Host $TestFileSummary "`r`n"
    }
}

# This test checks access to known file shares using a domain controller in each datacentre as well as a NAS share

If ($FileShareTest) {
    Clear-Variable -Name FileShareTesting, FileConnectivityLog, FileShareTestSummary -ErrorAction SilentlyContinue
    Write-Host "`r`nConnecting to the Netlogon share on domain controllers in both datacentres as well as the main NAS`r`n"
    $FileShareTesting = FileShareTest
    $FileConnectivityLog = $FileShareTesting[0]
    $FileShareTestSummary = $FileShareTesting[1]
    
    $x=0
    "{0,-30} {1,-30}" -f  "Fileshare Host", "Connection Test Result`r`n"
    for (;$x -le 2;$x++){
        "{0,-30} {1,-30}" -f  $FileConnectivityLog[$x][0], $FileConnectivityLog[$x][1]
    }
    Write-Host "`r"
}

# This reports all group policies that the machine and user have applied to them

If ($GroupPolicyCheck){
    Clear-Variable GPRes, x, OU, OUSplit, strtmp, userOU, GPOApplied, GPRes, GPOAppliedDate, GPOAppliedTime, GPOAppliedfrom, SectionCount, AppliedGPOs, GroupMembership, Line, y, Filter, Searcher, attrib, MachineOU, MachineOUSplit, strtmp, ComputerOU -ErrorAction SilentlyContinue
    $GPRes = gpresult /r
    $OU = $GPRes | Select-String -Pattern "CN="
    $OUSplit = $OU -split(",")
    [array]::Reverse($OUSplit)
    $x=2
    for (;$x -le $OUSplit.count -2;$x++){
        $strtmp = $OUSplit[$x].trim()
        $UserOU = $UserOU + "\" + $strtmp.substring(3)
    }
    $UserOU = $UserOU.substring(1)

    [String]$GPOApplied = $GPRes | Select-String -Pattern "Last time"
    $GPOApplied = $GPOApplied.trim()
    $GPOApplied = $GPOApplied.Substring(36)
    $GPOApptmp = $GPOApplied.split(" ")
    $GPOAppliedDate = $GPOApptmp[0]
    $GPOAppliedTime = $GPOApptmp[2]

    [String]$GPOAppliedFrom = $GPRes | Select-String -Pattern "Group Policy was applied from:"
    $GPOAppliedfrom = $GPOAppliedfrom.trim()
    $GPOAppliedfrom = $GPOAppliedfrom.Substring(36)

    $SectionCount = 0
    $AppliedGPOs = @()
    $GroupMembership = @()

    foreach($line in $GPRes) {
        if ($line -match "----"){$SectionCount=$SectionCount+1}

        if ($sectionCount -eq 3) {
            if ($line -notmatch "----") {
                if ($line -notmatch "following GPOs were not applied") {
                    if ($line.length -gt 0){$AppliedGPOs += , $line.trim()}
                }
            }
        }
        if ($sectionCount -eq 5) {
            if ($line -notmatch "----") {
                if ($line.length -gt 0){$GroupMembership += , $line.trim()}
            }
        }
    }
    $GroupMembership = $GroupMembership | Sort-Object

    $Filter = "(&(name=" + $env:computername +  "))"
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($RootOU)")
    $Searcher.Filter = $Filter
    $Searcher.SearchScope =  "Subtree"
    $attrib=$Searcher.FindAll() | select -ExpandProperty properties
    $MachineOU = $attrib.distinguishedname

    $MachineOUSplit = $MachineOU -split(",")
    [array]::Reverse($MachineOUSplit)
    $x=2
    for (;$x -le $MachineOUSplit.count -2;$x++){
        $strtmp = $MachineOUSplit[$x].trim()
        $ComputerOU = $ComputerOU + "\" + $strtmp.substring(3)
    }
    $ComputerOU = $ComputerOU.substring(1)

    Write-Host "`r`nUser OU: " $UserOU
    Write-Host "`r`nComputer OU: " $ComputerOU "`r`n"
    Write-Host "GPO Applied: " $GPOAppliedDate " at " $GPOAppliedTime
    Write-Host "GPO Applied From: " $GPOAppliedfrom
    Write-host "`r`nApplied GPOs:`r`n"
    foreach ($y in $AppliedGPOs){
        Write-host $y
    }
    Write-Host "`r`nGroup Memberships:"
    Foreach ($y in $GroupMembership){
        Write-host $y
    }
    Write-Host "`r`n"
}

# This displays the reported Windows security hotfixes that have been installed

If ($Hotfixes) {
    Clear-Variable -Name Hotfixinfo, HotfixList -ErrorAction SilentlyContinue
    $Hotfixinfo = CheckInstalledHotfixes
    $HotfixList = $Hotfixinfo[0]
    Write-Host "`r`nChecking for recently installed hotfixes`r`n"
    $Hotfixcount = $HotfixList.count

    If ($HotfixList.count -gt 0) {
        $x=0
        "{0,-20} {1,-20} {2,-20}" -f  "Hofix Type", "Hotfix ID", "Installed On`r`n"
        for (;$x -le $Hotfixcount;$x++){
            "{0,-20} {1,-20} {2,-20}" -f  $HotfixList[$x][0], $HotfixList[$x][1], $HotfixList[$x][2] 
        }
    } else {
       Write-Host "Hotfixes installed: None"
    }
}

#This reports all IP information for the local machine, including the routing table

If ($IPInfo) {
    Clear-Variable AllIPInfo, AllIP, AdapterCount, x, DNSSuffix, DNSServers, RoutePrint, RouteInfo, NetDestination, DestSubMaskSlash, DestSubMask, NextHop, IFMetric, tmp2, temp1, temp2, temp3, temp4 -ErrorAction SilentlyContinue
    $AllIPInfo = GetIPInfo
    $AllIP = $AllIPInfo[0]
    $AdapterCount = ALLIPInfo[1]
    Write-Host "`r`nIP Info`r`n"
    $x=0

    for (;$x -le $ALLIP.count -1;$x++){
        $DNSSuffix = $ALLIP[$x][2]
           $DNSServers = $ALLIP[$x][12]
        "{0,-30} {1,-30}" -f  "Adapter", $ALLIP[$x][3]
        "{0,-30} {1,-30}" -f  "Connection Type", $ALLIP[$x][0]
        "{0,-30} {1,-30}" -f  "Connection Location", $ALLIP[$x][1]
        "{0,-30} {1,-30}" -f  "IP Address", $ALLIP[$x][9]
        "{0,-30} {1,-30}" -f  "Subnet Mask", $ALLIP[$x][10]
        "{0,-30} {1,-30}" -f  "Default Gateway", $ALLIP[$x][11]
        "{0,-30} {1,-30}" -f  "DNS Servers", $DNSServers[0]
       $y=1
        If ($DNSServers.Count -gt 1) {
            For (;$y -le $DNSServers.Count -1;$y++) {
                "{0,-30} {1,-30}" -f  " ", $DNSServers[$y]
            }
        }
        "{0,-30} {1,-30}" -f  "MAC Address", $ALLIP[$x][4]
        "{0,-30} {1,-30}" -f  "DNS Suffix Search List", $DNSSuffix[0]
        $y=0
        If ($DNSSuffix.Count -gt 1) {
            For (;$y -le $DNSSuffix.Count -1;$y++) {
                "{0,-30} {1,-30}" -f  " ", $DNSSuffix[$y]
            }
        }
        "{0,-30} {1,-30}" -f  "DHCP Enabled", $ALLIP[$x][5]
        "{0,-30} {1,-30}" -f  "DHCP Server", $ALLIP[$x][6]
        "{0,-30} {1,-30}" -f  "DHCP Lease Obtained", $ALLIP[$x][7]
        "{0,-30} {1,-30}" -f  "DHCP Lease Expires", $ALLIP[$x][8]
        "{0,-30} {1,-30}" -f  "DHCP Class ID", $AllIP[$x][13]
        write-host "`r`n"
    }

    $RoutePrint = @()
    $RouteInfo = get-netroute -AddressFamily IPv4 | ForEach-Object {$_.Destinationprefix, $_.NextHop, $_.InterfaceMetric}
    for ($x=0;$x -le $RouteInfo.count -1;$x=$x+3) {
        Clear-Variable -name NetDestination, DestSubMaskSlash, DestSubMask, NextHop, IFMetric, tmp2 -ErrorAction SilentlyContinue
        $NetDestination = ($RouteInfo[$x] -split "/")[0]
        $DestSubMaskSlash = [int]($RouteInfo[$x] -split "/")[1]
        $DestSubMask = Convert-RvNetInt64ToIpAddress -Int64 ([convert]::ToInt64(('1' * $DestSubMaskSlash + '0' * (32 - $DestSubMaskSlash)), 2))
        $NextHop = $RouteInfo[$x+1]
        $IFMetric = $RouteInfo[$x+2]
        $tmp2 = $NetDestination, $DestSubMask, $NextHop, $IFMetric
        $RoutePrint += , $tmp2
    }

    Write-Host "IPV4 Routing Table"
    "{0,-30} {1,-30} {2,-30} {3,-30}" -f  "`r`nDestination Address","Destination Subnet Mask","Gateway Address","Interface Metric`r`n" 
    for ($y=0;$y -le $RoutePrint.count -1;$y++) {
        Clear-Variable temp1, temp2, temp3, temp4 -ErrorAction SilentlyContinue
        $temp1 = $RoutePrint[$y][0]
        $temp2 = $RoutePrint[$y][1]
        $temp3 = $RoutePrint[$y][2]
        $temp4 = $RoutePrint[$y][3]
        "{0,-30} {1,-30} {2,-30} {3,-30}" -f  $temp1, $temp2, $temp3, $temp4 
    }

}

# This tests connectivity to internal website

If ($InternalWebTest) {

    Write-Host "`r`nTesting connection on TCP80 and TCP443 to internal website`r`n" 
    Clear-Variable -Name InternalWebTesting, InternalWebTestSummary, tmp1 tmp2, tmp3, tmp4, intwebtest -ErrorAction SilentlyContinue
    $InternalWebTesting = InternalWebTest
    $IntWebTest = $InternalWebTesting[0]
    $InternalWebTestSummary = $InternalWebTesting[1]
    $x=0
    for (;$x -le $IntWebTest.count -1;$x++){
        $tmp1 = [string]$IntWebTest[$x].Computername
        $tmp2 = [string]$IntWebTest[$x].RemoteAddress.IPAddressToString
        If ($x -eq 0) {$tmp3 = "80"} else {$tmp3 = "443"}
        $tmp4 = [string]$IntWebTest[$x].TcpTestSucceeded
        "{0,-30} {1,-30}" -f  "Remote Hostname: ", $tmp1
        "{0,-30} {1,-30}" -f  "Remote Host IP: ", $tmp2
        "{0,-30} {1,-30}" -f  "Remote Host Port: ", $tmp3
        "{0,-30} {1,-30}" -f  "Connection Result: ", $tmp4 + "`r`n"
    }
}

# This test displays the local PC information

If ($MachineInfo) {
    Clear-Variable -Name MachineInformation, DomainName, PCModel, OSVersion, Vol, tmp, tmp1 -ErrorAction SilentlyContinue
    $MachineInformation = GetMachineInfo
    Write-Host "`r`nBasic Machine Infomation`r`n"
    "{0,-30} {1,-30}" -f "Domain:", $MachineInformation[0]
    "{0,-30} {1,-30}" -f "Logon Sevrer:", $MachineInformation[6]
    "{0,-30} {1,-30}" -f "PC Model:", $MachineInformation[1]
    "{0,-30} {1,-30}" -f "BIOS Ver", $MachineInformation[2]
    $tmp = [string]$MachineInformation[3] + " (" + [string]$MachineInformation[4] + ")"
    "{0,-30} {1,-30}" -f "Windows Version:", $tmp
    $tmp = $MachineInformation[5]
    foreach ($Vol in $tmp){
        $tmp1 = [string]$vol[1]+"GB"
        $tmp2 = [string]$Vol[2]+"GB"
        "{0,-10} {1,-5} {2,-10} {3,-10} {4,-10} {5,-10}" -f "Volume:", $Vol[0], "Disk Size:", $tmp1, "Free Space:", $tmp2
    }
}

#This test shows the NTP Info for the client
If ($NTP){
    $NTPTmp = w32tm /query /status
    Write-host "`r`nWorkstation NTP information`r`n"
    If ($NTPTmp -notmatch "The service has not been started"){
        [String]$SyncTime = $NTPTmp | Select-String -Pattern "Last Successful Sync Time"
        $SyncTime = $SyncTime.Substring(27)
        [String]$NTPSource = $NTPTmp | Select-String -Pattern "Source: "
        $NTPSource =$NTPSource.Substring(8)
        "{0,-30} {1,-30}" -f  "NTP server:", $NTPSource + "`r`n"
        "{0,-30} {1,-30}" -f  "Last Sync Time:", $SyncTime + "`r`n"
    } else {
        Write-host "NTP Service not started"
    }
}

#This test pings domain controllers to check basic connectivity to each datacentre
If ($DCPing) {
    Clear-Variable -Name svrs, ICMPTest, PingResults, TargetDC, FailurSummary -ErrorAction SilentlyContinue
    $svrs = $DomainController1InDC1,$DomainController2InDC1,$DomainController1InDC2,$DomainController2InDC2
    $ICMPTest = PingTest $svrs
    Write-Host "`r`nPinging Domain Controllers 1 and 2 in both datacentres and local GW (when on LAN)`r`n"
    $PingResults = $ICMPTest[0]
    $FailureSummary = $ICMPTest[1]
    If ($FailureSummary -gt 0) {
        Write-Host "$FailureSummary Domain Controller(s) could not be contacted`r`n"
    } else {
        Write-Host "All DCs were successfully contacted`r`n"
    }
    $x = 0
    for (;$x -le $PingResults.count -1;$x++){
        Write-Host "Destination Server: " $PingResults[$x][0]
        Write-Host "Ping Succeeded: " $PingResults[$x][5]
        Write-Host "Interface: " $PingResults[$x][2]
        Write-Host "Source Address: " $PingResults[$x][3]
        Write-Host "Next Route Hop: " $PingResults[$x][4]
        Write-Host "ICMP Response Time: " $PingResults[$x][6] "ms`r`n"
    }
}

# This test checks DNS information for several key elements: domain controllers at each data centre, the MS federation STS stack (both internal and external) and Microsoft.com to check internet DNS in general

If ($DNSServiceCheck) {
    $Svrs = $ExtDNS1, $ExtDNS2
    $ICMPTest = PingTest $svrs 53
    $PingResults = $ICMPTest[0]
    $FailureSummary = $ICMPTest[1]
    If ($FailureSummary -gt 0) {
        Write-Host "$FailureSummary DNS Server(s) could not be contacted`r`n"
    } else {
        Write-Host "Both Internet facing DNS Servers successfully contacted`r`n"
    }
    $x = 0
    Clear-Variable ExtSvr -ErrorAction SilentlyContinue
    for (;$x -le $PingResults.count -1;$x++){
        If ($PingResults[$x][0]){$ExtSvr = $PingResults[$x][2]}
        $tmp1 = $PingResults[$x][1]
        $tmp2 = $PingResults[$x][0]
        $tmp3 = $PingResults[$x][2]
        "{0,-30} {1,-30}" -f  "Destination Server:", $tmp3
        "{0,-30} {1,-30}" -f  "Interface name:", $tmp2
        "{0,-30} {1,-30}" -f  "Port 53 Ping test result:", $tmp1 + "`r`n"
        Clear-Variable tmp1, tmp2 -ErrorAction SilentlyContinue
    }
    If ($ExtSvr.length -eq 0){$ExtSvr = "None"}

    Clear-Variable -Name DNSInfo, DNSLog, DNSTestSummary, ConnectivityTestServers -ErrorAction SilentlyContinue
    $ConnectivityTestServers = $DomainController1NameInDC1, $DomainController1NameInDC2, $STSServer, "microsoft.com"
    $DNSInfo = DNSTest $ConnectivityTestServers A In
    $DNSLog = $DNSInfo[0]
    $DNSTestSummary = $DNSInfo[1]
    $x=0
    Write-Host "`r`nResolving internal federation addres, Domain Controllers in both datacentres as well as Microsoft.co.uk`r`n"
    Write-Host $DNSTestSummary "`r`n"

    "{0,-30} {1,-30} {2,-30} {3,-30}" -f  "Destination Hostname", "Resolved IP Address", "Name Administrator", "Serial Number`r`n"
    for (;$x -le $DNSLog.count - 1;$x++) {
        "{0,-30} {1,-30} {2,-30} {3,-30}" -f  $DNSLog[$x][0], $DNSLog[$x][1], $DNSLog[$x][2], $DNSLog[$x][3] # + "`r"
    }

    Clear-Variable -Name DNSInfo, DNSLog, DNSTestSummary, ConnectivityTestServers -ErrorAction SilentlyContinue
    $ConnectivityTestServers = $STSServer
    $DNSInfo = DNSTest $ConnectivityTestServers A Ext $ExtSvr
    $DNSLog = $DNSInfo[0]
    $DNSTestSummary = $DNSInfo[1]
    $x=0
    Write-Host "`r`nResolving external federation addres`r`n"
    Write-Host $DNSTestSummary "`r`n"

    "{0,-30} {1,-30} {2,-30} {3,-30}" -f  "Destination Hostname", "Resolved IP Address", "Name Administrator", "Serial Number`r`n"
    for (;$x -le $DNSLog.count - 1;$x++) {
        "{0,-30} {1,-30} {2,-30} {3,-30}" -f  $DNSLog[$x][0], $DNSLog[$x][1], $DNSLog[$x][2], $DNSLog[$x][3] + "`r`n"
    }

}

# This test shows the SCCM service status

If ($SCCMSVCTest) {
    Clear-Variable -Name SCCMStatus -ErrorAction SilentlyContinue
    $SCCMSVCStatus = CheckSCCMClientService
    Write-Host "`r`nSCCM Client Information`r`n"
    Write-Host "SCCM client installed: " $SCCMSVCStatus[0]
    if ($SCCMSVCStatus[0] -eq "Yes") {
        Write-Host "SCCM status: " $SCCMSVCStatus[1]
        Write-Host "SCCM Client Version: " $SCCMSVCStatus[2] "`r`n"
    }
}

# This test provides a traceroute to each datacentre, using a domain controller in each
If ($DCTraceRoute) {

    Clear-Variable -Name TraceRouteOutput, tmp -ErrorAction SilentlyContinue
    Write-Host "`r`nRunning a TraceRoute to Domain Controllers in both datacentres"
    $TraceRouteOutput = TraceRouteTest
    $y=0
    for (;$y -le $TraceRouteOutput.count -1;$y++){
        $tmp = $TraceRouteOutput[$y].remoteaddress.IPAddressToString
        if ([string]::IsNullOrEmpty($tmp)) {
            $tmp = $TraceRouteOutput[$y].ComputerName
            write-host "Unable to contact $tmp, so a trace route was not possible"
        } else {
            "{0,-30} {1,-30}" -f  "`r`n",""
            "{0,-30} {1,-30}" -f  "Remote host name:", $TraceRouteOutput[$y].ComputerName
            "{0,-30} {1,-30}" -f  "Resolved IP Address:", $TraceRouteOutput[$y].remoteaddress.IPAddressToString
            "{0,-30} {1,-30}" -f  "Interface:", $TraceRouteOutput[$y].InterfaceDescription
            "{0,-30} {1,-30}" -f  "Source IP Address:", $TraceRouteOutput[$y].SourceAddress.IPAddress
            "{0,-30} {1,-30}" -f  "Ping succeeded:", $TraceRouteOutput[$y].PingSucceeded
            "{0,-30} {1,-30}" -f  "Ping response time:", $TraceRouteOutput[$y].PingReplyDetails.RoundtripTime
            $x=0
            Write-host "Hops:"
            for (;$x -le $TraceRouteOutput[$y].traceroute.count - 1;$x++) {
                $tmp = [string]$TraceRouteOutput[$y].TraceRoute[$x]
                if ($tmp -ne "0.0.0.0"){
                    "{0,-30} {1,-30}" -f  "", $tmp
                }
            }
        }
        Write-Host "`r`n"
    }
}

####################

# Full Testing Set #

####################

# All information gathered in the following section is held in variables, so that it can be inserted easily into SQL and it is also formatted for ease of reading in the report that is generated at the end.

if ($PSBoundParameters.Count -eq 0) {
    $wshell = New-Object -ComObject Wscript.Shell
    $host.ui.RawUI.WindowTitle = "Through Technology Client Support Information Script"

    # Get Username from registry and password from end user
    # While local credentials are used for on-prem service access, connecting to O365 SharePoint requires the users email address as the identifier, which is not always the UPN used on the domain, so it needs to be checked.

    Clear-Variable -Name Key, User, Password -ErrorAction SilentlyContinue
    # Last logged on user is checked in the registry, to see if that contains the email address

    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\currentversion\authentication\logonui'
    $Usertmp = (Get-ItemProperty -Path $key -Name lastloggedonuser).lastloggedonuser
    if ($usertmp -match "@"){
        $user = $Usertmp
    } else {
        # If the email address is not found, a domain query is used and the UPN checked.

        $userenvtmp = $env:username
        if ($userenvtmp -match "\\"){$userenvtmp = $userenvtmp.split("\")[1]}
        $tmp = get-aduser -filter 'samaccountname -eq $userenvtmp' | ForEach-Object {$_.userprincipalname}
        if ($tmp -match "@") {
            $user = $tmp
        } else {
            # In case 'get-aduser' fails to return the information, the following routine is used:

            $Filter = "(&(samaccountname=" + $userenvtmp +  "))"
            $Searcher = New-Object DirectoryServices.DirectorySearcher
            $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($RootOU)")
            $Searcher.Filter = $Filter
            $Searcher.SearchScope =  "Subtree"
            $attrib=$Searcher.FindAll() | select -ExpandProperty properties
            $tmp = $attrib.userprincipalname
            if ($tmp -match "@") {
                $user = $tmp
            } else {
                $user = Read-Host -Prompt "Please enter your email address"
            }
        }
    }

    # The password for O365 cannot be reliably gleaned programatically, so asking for it is the best option

    $Password = Read-Host -Prompt "Please enter the Password for $user to securely upload the log file" –AsSecureString

    #Machine info
    Clear-Variable -Name MachineInformation, DomainName, PCModel, OSVersion -ErrorAction SilentlyContinue
    Write-Progress -Activity "Getting machine information" -Status "5% Complete:" -PercentComplete 5
    $MachineInformation = GetMachineInfo
    $DomainName = $MachineInformation[0]
    $PCModel = $MachineInformation[1]
    $BIOSVersion = $MachineInformation[2]
    $OSVersion = $MachineInformation[3] |  ForEach-Object {$_.major}
    $WindowsReleaseVersion = $MachineInformation[4]
    $LogonServerName = $MachineInformation[6]

    # The logon server names contain site codes, this translates the code into a user readable format

    If ($LogonServerName -match $DC1Code){
        $LogonServerLocation = $DC1Name
    } elseif ($LogonServerName -match $DC2Code){
        $LogonServerLocation = $DC2Name
    }

    #GroupPolicyCheck

    Clear-Variable GPRes, x, OU, OUSplit, strtmp, userOU, GPOApplied, GPRes, GPOAppliedDate, GPOAppliedTime, GPOAppliedfrom, SectionCount, AppliedGPOs, GroupMembership, Line, y, Filter, Searcher, attrib, MachineOU, MachineOUSplit, strtmp, ComputerOU -ErrorAction SilentlyContinue
    $GPRes = gpresult /r
    $OU = $GPRes | Select-String -Pattern "CN="
    $OUSplit = $OU -split(",")
    [array]::Reverse($OUSplit)
    $x=2
    for (;$x -le $OUSplit.count -2;$x++){
        $strtmp = $OUSplit[$x].trim()
        $UserOU = $UserOU + "\" + $strtmp.substring(3)
    }
    $UserOU = $UserOU.substring(1)

    [String]$GPOApplied = $GPRes | Select-String -Pattern "Last time"
    $GPOApplied = $GPOApplied.trim()
    $GPOApplied = $GPOApplied.Substring(36)
    $GPOApptmp = $GPOApplied.split(" ")
    $GPOAppliedDate = $GPOApptmp[0]
    $GPOAppliedTime = $GPOApptmp[2]

    [String]$GPOAppliedFrom = $GPRes | Select-String -Pattern "Group Policy was applied from:"
    $GPOAppliedfrom = $GPOAppliedfrom.trim()
    $GPOAppliedfrom = $GPOAppliedfrom.Substring(36)

    $SectionCount = 0
    $AppliedGPOs = @()
    $GroupMembership = @()

    foreach($line in $GPRes) {
        if ($line -match "----"){$SectionCount=$SectionCount+1}

        if ($sectionCount -eq 3) {
            if ($line -notmatch "----") {
                if ($line -notmatch "following GPOs were not applied") {
                    if ($line.length -gt 0){$AppliedGPOs += , $line.trim()}
                }
            }
        }
        if ($sectionCount -eq 5) {
            if ($line -notmatch "----") {
                if ($line.length -gt 0){$GroupMembership += , $line.trim()}
            }
        }
    }
    $GroupMembership = $GroupMembership | Sort-Object

    Clear-Variable AllAppliedGPOs, line -ErrorAction SilentlyContinue
    Foreach ($line in $AppliedGPOs){
        $AllAppliedGPOs = $AllAppliedGPOs + "`r`n" + $line
    }

    Clear-Variable AllAppliedGPOs, line -ErrorAction SilentlyContinue
    Foreach ($line in $AppliedGPOs){
        $AllAppliedGPOs = $AllAppliedGPOs + $line + "`r`n"
    }
    $x=0
    for (;$x -le $GroupMembership.count -1; $x++){
        $AllGroupMemberships = $AllGroupMemberships + $GroupMembership[$x] + "`r`n" #, $GroupMembership[$x+1]
    }

    $Filter = "(&(name=" + $env:computername +  "))"
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($RootOU)")
    $Searcher.Filter = $Filter
    $Searcher.SearchScope =  "Subtree"
    $attrib=$Searcher.FindAll() | select -ExpandProperty properties
    $MachineOU = $attrib.distinguishedname

    $MachineOUSplit = $MachineOU -split(",")
    [array]::Reverse($MachineOUSplit)
    $x=2
    for (;$x -le $MachineOUSplit.count -2;$x++){
        $strtmp = $MachineOUSplit[$x].trim()
        $ComputerOU = $ComputerOU + "\" + $strtmp.substring(3)
    }
    $ComputerOU = $ComputerOU.substring(1)

    #SCCM status
    Clear-Variable -Name SCCMStatus -ErrorAction SilentlyContinue
    Write-Progress -Activity "Getting SCCM service status" -Status "7% Complete:" -PercentComplete 7
    $SCCMSVCStatus = CheckSCCMClientService
    $SCCMSVCSummary = $SCCMSVCStatus[0]
    $SCCMSVCRunning = $SCCMSVCStatus[1]
    $SCCMClientVersion = $SCCMSVCStatus[2]

    #NTP Info
    $NTPTmp = w32tm /query /status
    If ($NTPTmp -notmatch "The service has not been started"){
        [String]$SyncTime = $NTPTmp | Select-String -Pattern "Last Successful Sync Time"
        $SyncTime = $SyncTime.Substring(27)
        [String]$NTPSource = $NTPTmp | Select-String -Pattern "Source: "
        $NTPSource =$NTPSource.Substring(8)
    } else {
        $NTPSource = "NTP Service not started"
    }

    #Hotfix Info
    Clear-Variable -Name Hotfixinfo, HotfixInstallSummary, HotfixList, RecentHotfixes -ErrorAction SilentlyContinue
    Write-Progress -Activity "Checking Hotfix history" -Status "10% Complete:" -PercentComplete 10
    $Hotfixinfo = CheckInstalledHotfixes
    $RecentHotfixes = $Hotfixinfo[0]
    $HotfixInstallSummary = $Hotfixinfo[1]
    $Hotfixcount = $RecentHotfixes.count 
    If ($RecentHotfixes.count -gt 0) {
        $x=0
        $HotFixesInstalled = "{0,-30} {1,-30} {2,-30}" -f  "Hofix Type", "Hotfix ID", "Installed On`r`n"
        for (;$x -le $Hotfixcount;$x++){
            $HotFixesInstalled = $HotFixesInstalled + "`r`n" + "{0,-30} {1,-30} {2,-30}" -f  $RecentHotfixes[$x][0], $RecentHotfixes[$x][1], $RecentHotfixes[$x][2] 
        }
    } else {
       $HotFixesInstalled = "None"
    }

    # Defender info
    Clear-Variable -Name DefenderInfo, DefenderAllInfo, DefenderAVSummary, DefenderLastUpdate -ErrorAction SilentlyContinue
    Write-Progress -Activity "Checking Windows Defender Status" -Status "15% Complete:" -PercentComplete 15
    $DefenderInfo = GetDefenderStatus

    $AMProductVersion = $DefenderInfo[0]
    $AMEngineVersion = $DefenderInfo[1]
    $AMServiceEnabled = $DefenderInfo[2]
    $AntispywareEnabled = $DefenderInfo[3]
    $AntispywareSignatureLastUpdated = $DefenderInfo[4]
    $AntispywareSignatureVersion = $DefenderInfo[5]
    $AntivirusEnabled = $DefenderInfo[6]
    $AntivirusSignatureLastUpdated = $DefenderInfo[7]
    $AntivirusSignatureVersion = $DefenderInfo[8]
    $NISEnabled = $DefenderInfo[9]
    $NISEngineVersion = $DefenderInfo[10]
    $NISSignatureLastUpdated = $DefenderInfo[11]
    $NISSignatureVersion = $DefenderInfo[12]
    $OnAccessProtectionEnabled = $DefenderInfo[13]
    $RealTimeProtectionEnabled = $DefenderInfo[14]

    $DefenderAllInfo = $DefenderInfo[0] | Out-String
    $DefenderAllInfo = $DefenderAllInfo.trim()
    $DefenderAVSummary = $DefenderInfo[1]
    $DefenderLastUpdate = $DefenderInfo[2]

    $DefenderAllInfo = 
    "{0,-70} {1,-70}" -f "Anti-Malware Product Version", $DefenderInfo[0] + "`r`n" +
    "{0,-70} {1,-70}" -f "Anti-Malware Engine Version", $DefenderInfo[1] + "`r`n" +
    "{0,-70} {1,-70}" -f "Anti-Malware Service Enabled", $DefenderInfo[2] + "`r`n" +
    "{0,-70} {1,-70}" -f "Anti-spyware Enabled", $DefenderInfo[3] + "`r`n" +
    "{0,-70} {1,-70}" -f "Anti-spyware Signature Last Updated", $DefenderInfo[4] +  "`r`n" +
    "{0,-70} {1,-70}" -f "Anti-spyware Signature Version", $DefenderInfo[5] + "`r`n" +
    "{0,-70} {1,-70}" -f "Anti-virus Enabled", $DefenderInfo[6] + "`r`n" +
    "{0,-70} {1,-70}" -f "Anti-virus Signature Last Updated", $DefenderInfo[7] + "`r`n" +
    "{0,-70} {1,-70}" -f "Anti-virus Signature Version", $DefenderInfo[8] + "`r`n" +
    "{0,-70} {1,-70}" -f "Network Realtime Inspection Service Enabled", $DefenderInfo[9] + "`r`n" +
    "{0,-70} {1,-70}" -f "Network Realtime Inspection Service Engine Version", $DefenderInfo[10] + "`r`n" +
    "{0,-70} {1,-70}" -f "Network Realtime Inspection Service Signature Last Updated", $DefenderInfo[11] +"`r`n" +
    "{0,-70} {1,-70}" -f "Network Realtime Inspection Service Signature Version", $DefenderInfo[12] +"`r`n" +
    "{0,-70} {1,-70}" -f "On Access Protection Enabled", $DefenderInfo[13] +"`r`n" +
    "{0,-70} {1,-70}" -f "Real Time Protection Enabled",$DefenderInfo[14]

    if ($AntivirusEnabled -eq "True") {$DefenderAVSummary = "Running"} else {$DefenderAVSummary = "Not running"}

    #IPConfig Info
    Clear-Variable -Name AllIPInfo, AllIP, DisplayIPInfo, DNSTmp, DNSSvrTmp, DNSSuffix, tmp, tmp2, tmp3, tmp4, IPRouteInfo -ErrorAction SilentlyContinue
    Write-Progress -Activity "Getting IP information" -Status "20% Complete:" -PercentComplete 20
    $AllIPInfo = GetIPInfo
    $AllIP = $AllIPInfo[0]
    $x=0
    for (;$x -le $ALLIP.count - 1;$x++){
        $tmp = $ALLIP[$x][0]
        $tmp2 = $ALLIP[$x][1]
        $DNSSuffix = $ALLIP[$x][2]
       $DNSServers = $ALLIP[$x][12]
        $ConnectionType = $tmp + ", connected via: " + $tmp2
        If ($tmp -eq "RAS"){$RASConnection = $ConnectionType = $tmp + ", connected via: " + $tmp2}
        $y=0
        If ($DNSSuffix.Count -gt 1) {
            For (;$y -le $DNSSuffix.Count -1;$y++) {
                $DNSTmp = $DNSTmp + "{0,-30} {1,-30}" -f  " ", $DNSSuffix[$y] + "`r`n"
            }
        }
           $y=1
        If ($DNSServers.Count -gt 1) {
            For (;$y -le $DNSServers.Count -1;$y++) {
                      $tmp3 = [string]$DNSServers[$y]
                $DNSSvrTmp = $DNSSvrTmp + "{0,-30} {1,-30}" -f  " ", $tmp3 + "`r`n"
            }
        }
       $tmp4 = [string]$DNSServers[0]
        $DisplayIPInfo = $DisplayIPInfo +
        "`r`n" +
        "{0,-30} {1,-30}" -f  "Adapter", $ALLIP[$x][3] + "`r`n" +
        "{0,-30} {1,-30}" -f  "Connection Type", $ALLIP[$x][0] + "`r`n" +
        "{0,-30} {1,-30}" -f  "RAS Endpoint", $ALLIP[$x][1] + "`r`n" +
        "{0,-30} {1,-30}" -f  "IP Address", $ALLIP[$x][9] + "`r`n" +
        "{0,-30} {1,-30}" -f  "Subnet Mask", $ALLIP[$x][10] + "`r`n" +
        "{0,-30} {1,-30}" -f  "Default Gateway", $ALLIP[$x][11] + "`r`n" +
        "{0,-30} {1,-30}" -f  "DNS Servers", $tmp4 + "`r`n"
       if ($DNSSvrTmp.length -gt 0){$DisplayIPInfo = $DisplayIPInfo + $DNSSvrTmp}
       $DisplayIPInfo = $DisplayIPInfo +
           "{0,-30} {1,-30}" -f  "MAC Address", $ALLIP[$x][4] + "`r`n" +
        "{0,-30} {1,-30}" -f  "DNS Suffix Search List", $DNSSuffix[0] + "`r`n"
        if ($DNSTmp.length -gt 0){$DisplayIPInfo = $DisplayIPInfo + $DNSTmp}
        $DisplayIPInfo = $DisplayIPInfo +
        "{0,-30} {1,-30}" -f  "DHCP Enabled", $ALLIP[$x][5] + "`r`n" +
        "{0,-30} {1,-30}" -f  "DHCP Server", $ALLIP[$x][6] + "`r`n" +
        "{0,-30} {1,-30}" -f  "DHCP Lease Obtained", $ALLIP[$x][7] + "`r`n" +
        "{0,-30} {1,-30}" -f  "DHCP Lease Expires", $ALLIP[$x][8] + "`r`n" +
        "{0,-30} {1,-30}" -f  "DHCP Class ID", $AllIP[$x][13] + "`r`n"
        Clear-Variable DNSTmp, DNSSvrTmp -ErrorAction SilentlyContinue
    }

    $RoutePrint = @()
    $RouteInfo = get-netroute -AddressFamily IPv4 | ForEach-Object {$_.Destinationprefix, $_.NextHop, $_.InterfaceMetric}
    for ($x=0;$x -le $RouteInfo.count -1;$x=$x+3) {
        Clear-Variable -name NetDestination, DestSubMaskSlash, DestSubMask, NextHop, IFMetric, tmp2 -ErrorAction SilentlyContinue
        $NetDestination = ($RouteInfo[$x] -split "/")[0]
        $DestSubMaskSlash = [int]($RouteInfo[$x] -split "/")[1]
        $DestSubMask = Convert-RvNetInt64ToIpAddress -Int64 ([convert]::ToInt64(('1' * $DestSubMaskSlash + '0' * (32 - $DestSubMaskSlash)), 2))
        $NextHop = $RouteInfo[$x+1]
        $IFMetric = $RouteInfo[$x+2]
        $tmp2 = $NetDestination, $DestSubMask, $NextHop, $IFMetric
        $RoutePrint += , $tmp2
    }

    for ($y=0;$y -le $RoutePrint.count -1;$y++) {
        Clear-Variable temp1, temp2, temp3, temp4 -ErrorAction SilentlyContinue
        $temp1 = $RoutePrint[$y][0]
        $temp2 = $RoutePrint[$y][1]
        $temp3 = $RoutePrint[$y][2]
        $temp4 = $RoutePrint[$y][3]
        $IPRouteInfo = $IPRouteInfo +
        "{0,-30} {1,-30} {2,-30} {3,-30}" -f  $temp1, $temp2, $temp3, $temp4 +"`r`n" 
    }

    #DC Ping
    Clear-Variable -Name svrs, ICMPTest, PingResults, TargetDC, FailurSummary, PingLog -ErrorAction SilentlyContinue
    $svrs = $DomainController1InDC1, $DomainController2InDC1, $DomainController1InDC2, $DomainController2InDC2
    $ICMPTest = PingTest $svrs
    $PingResults = $ICMPTest[0]
    $FailureSummary = $ICMPTest[1]
    If ($FailureSummary -gt 0) {
        If ($FailureSummary -eq 1) {
            $PingTestSummary = "1 Domain Controller could not be contacted"
        } else {
            $PingTestSummary = "$FailureSummary Domain Controllers could not be contacted"
        }
    } else {
        $PingTestSummary = "All DCs were successfully contacted"
    }
    $x = 0
    for (;$x -le $PingResults.count -1;$x++){
        $PingLog = $PingLog +
        "`r`n" +
        "{0,-30} {1,-30}" -f  "Destination Server", $PingResults[$x][0] + "`r`n" +
        "{0,-30} {1,-30}" -f  "Ping Succeeded", $PingResults[$x][5] + "`r`n" +
        "{0,-30} {1,-30}" -f  "Interface", $PingResults[$x][2] + "`r`n" +
        "{0,-30} {1,-30}" -f  "Source Address", $PingResults[$x][3] + "`r`n" +
        "{0,-30} {1,-30}" -f  "Next Route Hop", $PingResults[$x][4] + "`r`n" +
        "{0,-30} {1,-30}" -f  "ICMP Response Time", $PingResults[$x][6] + "ms`r`n"
    }

    #Internet DNS server test

    $Svrs = $ExtDNS1, $ExtDNS2
    $DNSSvrPingTest = PingTest $svrs 53
    $Port53Results = $DNSSvrPingTest[0]
    $FailureSummary = $DNSSvrPingTest[1]
    If ($FailureSummary -gt 0) {
        $IntDNSTestSummary = "$FailureSummary DNS Server(s) could not be contacted`r`n"
    } else {
        $IntDNSTestSummary = "Both Internet facing DNS Servers successfully contacted`r`n"
    }
    $x = 0
    for (;$x -le $Port53Results.count -1;$x++){
        $tmp1 = $Port53Results[$x][1]
        $tmp2 = $Port53Results[$x][0]
        $tmp3 = $Port53Results[$x][2]
        $DNSSvrTestLog = $DNSSvrTestLog +
        "`r`n" +
        "{0,-30} {1,-30}" -f  "Destination: ", $tmp3+ "`r`n" +
        "{0,-30} {1,-30}" -f  "Interface name: ", $tmp2+ "`r`n" +
        "{0,-30} {1,-30}" -f  "Port 53 Ping test result: ", $tmp1 + "`r`n"
        Clear-Variable tmp1, tmp2, tmp3 -ErrorAction SilentlyContinue
    }

    #Resolving DNS
    Clear-Variable -Name DNSInfo, DNSLog, DNSTestSummary, ConnectivityTestServers, DNSResLog -ErrorAction SilentlyContinue
    Write-Progress -Activity "Checking DNS resolution" -Status "50% Complete:" -PercentComplete 50
    $ConnectivityTestServers = $DomainController1NameInDC1, $DomainController1NameInDC2, $STSServer, "microsoft.com"
    $DNSInfo = DNSTest $ConnectivityTestServers A In
    $DNSLog = $DNSInfo[0]
    $DNSTestSummary = $DNSInfo[1]
    $x=0
    for (;$x -le $DNSLog.count - 1;$x++) {
        $DNSResLog = $DNSResLog +
        "{0,-30} {1,-30} {2,-30} {3,-30}" -f  $DNSLog[$x][0], $DNSLog[$x][1], $DNSLog[$x][2], $DNSLog[$x][3] + "`r`n"
    }

    Clear-Variable ICMPTest, PingResults, ExtSvr -ErrorAction SilentlyContinue
    $ICMPTest = PingTest $ExtDNS1 53
    $PingResults = $ICMPTest[0]
    if ($PingResults[0][1]){
        $ExtSvr = $ExtDNS1
    } else {
        $ICMPTest = PingTest $ExtDNS2 53
        $PingResults = $ICMPTest[0]
        if ($PingResults[0][1]){
            $ExtSvr = $ExtDNS2
        } else {
            $ExtSvr = "None"
        }
    }

    If ($ExtSvr -notlike "None"){
        Clear-Variable -Name DNSInfo, DNSLog, DNSExtTestSummary, ConnectivityTestServers, DNSExtResLog -ErrorAction SilentlyContinue
        $ConnectivityTestServers = $STSServer
        $DNSInfo = DNSTest $ConnectivityTestServers A Ext $ExtSvr
        $DNSExtLog = $DNSInfo[0]
        $DNSExtTestSummary = $DNSInfo[1]
        $x=0
        for (;$x -le $DNSExtLog.count - 1;$x++) {
            $DNSExtResLog = $DNSExtResLog +
            "{0,-30} {1,-30} {2,-30} {3,-30}" -f $DNSExtLog[$x][0], $DNSExtLog[$x][1], $DNSExtLog[$x][2], $DNSExtLog[$x][3] + "`r"
        }
    }

#  Traceroute to both DCs

    Write-Progress -Activity "Running a TraceRoute to both datacentres" -Status "55% Complete:" -PercentComplete 55
    Clear-Variable -Name TraceRouteOutput, tmp, TraceRouteLog -ErrorAction SilentlyContinue
    $TraceRouteOutput = TraceRouteTest
    $y=0
    for (;$y -le $TraceRouteOutput.count -1;$y++){
        $tmp = $TraceRouteOutput[$y].remoteaddress.IPAddressToString
        if ([string]::IsNullOrEmpty($tmp)) {
            $tmp = $TraceRouteOutput[$y].ComputerName
            $TraceRouteLog = $TraceRouteLog + "Unable to contact $tmp, so a trace route was not possible"
        } else {
            $TraceRouteLog = $TraceRouteLog + "`r`n" +
            "{0,-30} {1,-30}" -f  "Remote host name:", $TraceRouteOutput[$y].ComputerName + "`r`n" +
            "{0,-30} {1,-30}" -f  "Resolved IP Address:", $TraceRouteOutput[$y].remoteaddress.IPAddressToString + "`r`n" +
            "{0,-30} {1,-30}" -f  "Interface:", $TraceRouteOutput[$y].InterfaceDescription + "`r`n" +
            "{0,-30} {1,-30}" -f  "Source IP Address:", $TraceRouteOutput[$y].SourceAddress.IPAddress + "`r`n" +
            "{0,-30} {1,-30}" -f  "Ping succeeded:", $TraceRouteOutput[$y].PingSucceeded + "`r`n" +
            "{0,-30} {1,-30}" -f  "Ping response time:", $TraceRouteOutput[$y].PingReplyDetails.RoundtripTime + "`r`nHops:`r`n"
            $x=0
            for (;$x -le $TraceRouteOutput[$y].traceroute.count - 1;$x++) {
                $tmp = [string]$TraceRouteOutput[$y].TraceRoute[$x]
                if ($tmp -ne "0.0.0.0"){
                    $TraceRouteLog = $TraceRouteLog + "{0,-30} {1,-30}" -f  "", $tmp + "`r`n"
                }
            }
        }
    }

#   Internal Web testing

    Write-Progress -Activity "Testing internal web connectivity" -Status "70% Complete:" -PercentComplete 70
    Clear-Variable -Name InternalWebTesting, InternalWebTestSummary, tmp1 tmp2, tmp3, tmp4, intwebtest, InternalWebTestLog -ErrorAction SilentlyContinue
    $InternalWebTesting = InternalWebTest
    $IntWebTest = $InternalWebTesting[0]
    $InternalWebTestSummary = $InternalWebTesting[1]
    $x=0
    $InternalWebTestLog = ""
    for (;$x -le $IntWebTest.count -1;$x++){
        $tmp1 = [string]$IntWebTest[$x].Computername
        $tmp2 = [string]$IntWebTest[$x].RemoteAddress.IPAddressToString
        If ($x -eq 0) {$tmp3 = "80"} else {$tmp3 = "443"}
        $tmp4 = [string]$IntWebTest[$x].TcpTestSucceeded
        $InternalWebTestLog = $InternalWebTestLog +
        "{0,-30} {1,-30}" -f  "Remote Hostname: ", $tmp1 + "`r`n" +
        "{0,-30} {1,-30}" -f  "Remote Host IP: ", $tmp2 + "`r`n" +
        "{0,-30} {1,-30}" -f  "Remote Host Port: ", $tmp3 + "`r`n" +
        "{0,-30} {1,-30}" -f  "Connection Result: ", $tmp4 + "`r`n`r`n"
    }

    #External web test

    Write-Progress -Activity "Testing external web connectivity" -Status "75% Complete:" -PercentComplete 75
    Clear-Variable -Name ExternalWebTesting, ExtWebChkErr, ExternalWebTestLog, tmp -ErrorAction SilentlyContinue

    $ExternalWebTesting = ExternalWebTest $ProxyLoadBalanceIP
    $ExternalWebTestSummary = $ExternalWebTesting[0]
    $ExtWebChkErr = $ExternalWebTesting[1]
    $WebSpeedCheck = $ExternalWebTesting[2]

    if ($ExtWebChkErr.length -gt 0) {
        $tmp = [string]$ExtWebChkErr.message
        $ExternalWebTestLog = "Failed to download the test file, Error:  " + $tmp
    } else {
        $ExternalWebTestLog = "Download of a 10MB file produced a speed result of: $WebSpeedCheck Mbps`r`n"
    }

    Clear-Variable ICMPTest, PingResults, FailureSummary, x, tmp1, tmp2 -ErrorAction SilentlyContinue
    $ICMPTest = PingTest $ProxyList 8080
    $PingResults = $ICMPTest[0]
    $FailureSummary = $ICMPTest[1]
    $x = 0
    Clear-Variable ExtSvr, VIPTesting -ErrorAction SilentlyContinue
    $VIPTesting = "{0,-40} {1,-40}" -f  "Proxy VIP", "Connection Result" + "`r`n`r`n"
    for (;$x -le $PingResults.count -1;$x++){
        $PxyIP = $PingResults[$x][2]
        $ProxyName = ProxyNameLookup $PxyIP
        If ($PingResults[$x][0]){$ExtSvr = $PingResults[$x][2]}
        $tmp1 = $PingResults[$x][2] + " (" + $ProxyName + ")"
        $tmp2 = $PingResults[$x][1] 
        $VIPTesting = $VIPTesting + "{0,-40} {1,-40}" -f  $tmp1, $tmp2 + "`r`n"
        Clear-Variable tmp1, tmp2 -ErrorAction SilentlyContinue
    }

    Clear-Variable -name Proxytestlog, IndividualProxytestlog -ErrorAction SilentlyContinue
    $Proxytestlog = TestIndividualProxies $ProxyList "https://bbc.co.uk"
    $x=0
    $IndividualProxytestlog = "{0,-40} {1,-40}" -f  "Proxy", "Connection Result" + "`r`n`r`n"

    For (;$x -le $Proxytestlog.count -1;$x++){
        $PxyIP = $Proxytestlog[$x][0]
        $ProxyName = ProxyNameLookup $PxyIP
        $tmp1 = $ProxyName + " (" + $Proxytestlog[$x][0] + ")"
        $tmp2 = $Proxytestlog[$x][1]
        $IndividualProxytestlog = $IndividualProxytestlog + "{0,-40} {1,-40}" -f  $tmp1, $tmp2 + "`r`n"
    }

    #File share testing
    Write-Progress -Activity "Testing file share connectivity" -Status "80% Complete:" -PercentComplete 80
    Clear-Variable -Name FileShareTesting, FileConnectivityLog, FileShareTestSummary, FileConnectivityTest, tmp1, tmp2 -ErrorAction SilentlyContinue
    $FileShareTesting = FileShareTest
    $FileConnectivityTest = $FileShareTesting[0]
    $FileShareTestSummary = $FileShareTesting[1]
    
    $x=0
    $FileConnectivityLog = "{0,-30} {1,-30}" -f  "Fileshare Host", "Connection Test Result"
    $FileConnectivityLog = $FileConnectivityLog + "`r`n`r`n"
    for (;$x -le 2;$x++){
        $tmp1 = $FileConnectivityTest[$x][0]
        $tmp2 = $FileConnectivityTest[$x][1]
        $FileConnectivityLog = $FileConnectivityLog + "{0,-30} {1,-30}" -f  $tmp1, $tmp2 + "`r`n"
    }

    $datestamp = get-date
    Write-Progress -Activity "Writing log file" -Status "95% Complete:" -PercentComplete 95
    If ($ErrorLog.length -eq 0){$ErrorLog = "None"}

    #File write speed test
    Clear-Variable Datestamp, FileSpeedCheck, FileWriteTestSummary -ErrorAction SilentlyContinue
    $error.Clear()
    Clear-Variable tmp, x -ErrorAction SilentlyContinue
    $x=0
    # Language Mode restrictions on the build prevent the creation of blank files using system.io.file, so the test file has to be created manually
    for (;$x -le 100; $x++){
        $tmp = $tmp + "xxxxxxxx"
    }
    $x=0
    for (;$x -le 14; $x++){
        $tmp = $tmp + $tmp
    }

    $FileName = $env:computername + "-CSIFileWriteTest.txt"
    $FullPath = $env:userprofile + "\" + $FileName
    $DestinationPath = $FileShareFullPath
    $DestinationFullPath = $FileShareFullPath + "\" + $FileName
    write-output $tmp | out-file $FullPath
    if (Test-Path $FileShareFullPath){
        $DateStamp = Get-Date
        $CopyTmp = Copy-Item $FullPath -Destination $DestinationPath -PassThru -ErrorAction SilentlyContinue
        If ($CopyTmp){
            $FileSpeedCheck = $((10/((Get-Date)-$datestamp).TotalSeconds)*8)
            $FileSpeedCheck = [math]::Round($FileSpeedCheck,2)
            $FileSpeedCheck = "File copied at an average of " + [string]$FileSpeedCheck + "mbps"
            Remove-Item –path $DestinationFullPath
            Remove-Item –path $FullPath
        } else {
            $FileSpeedCheck = "Unable to open the target folder`r`n"
        }
    } else {
        $FileSpeedCheck = "Failed to create the test file"
    }


    ###########################

    # Writing all data to SQL #

    ###########################

    # For deployment, PowerShell needs to be updated with 'Install-Module -Name SqlServer' (to be applied with Admin rights)


    #Elements remaining to be added here:

    # $FileSpeedCheck
    # InfoBlox Info
    # GPO Info

    $sqlConnection = New-Object System.Data.SqlClient.SqlConnection $ConnectionString
    $sqlConnection.Open()
    if ($sqlConnection.state -eq "open") {
        $DateStamp = Get-Date -format "yyyyMMdd HH:mm:ss"

        #Writing Machine Info to SQL

        $SQLInsert = "INSERT INTO [csidb].[dbo].[tbl_machineinfo](machinename,datestamp,username,Domainname,logonserver,pcmodel,biosversion,windowsversion,windowsreleaseversion,NTPServer,NTPLastSync)`r`n" +
        "VALUES ('$env:computername','$datestamp','$User','$DomainName', '$LogonServerName','$PCModel','$BIOSVersion','$OSVersion','$WindowsReleaseVersion','$NTPSource','$SyncTime')`r`n"

        #Writing Disk info to SQL
        $tmp = $MachineInformation[5]
        foreach ($Vol in $tmp){
            $tmp0 = [String]$Vol[0]
            $tmp1 = [string]$vol[1]
            $tmp2 = [string]$Vol[2]
            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_DiskInfo](machinename,datestamp,username,DiskLabel,DiskSize,DiskFreeSpace)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$tmp0','$tmp1','$tmp2')`r`n"
            $SQLInsert = $SQLInsert + $InsertResults
            Clear-Variable tmp0, tmp1, tmp2, InsertResults -ErrorAction SilentlyContinue
        }
        Clear-Variable tmp, vol -ErrorAction SilentlyContinue

        #Writing Hotfix Info to SQL
        $Hotfixcount = $RecentHotfixes.count - 1
        If ($RecentHotfixes.count -gt 0) {
            $x=0
            for (;$x -le $Hotfixcount;$x++){
                if (-not $RecentHotfixes[$x][0] -eq "") {
                    $tmp1 = $RecentHotfixes[$x][0]
                    $tmp2 = $RecentHotfixes[$x][1]
                    $tmp3 = $RecentHotfixes[$x][2]

                    $HotfixCheck = Invoke-sqlcmd -Query "select * from csidb.dbo.tbl_hotfixes where hotfixid='$tmp2' and machinename='$env:computername'"
                    if ($HotfixCheck.count -eq 0) {
                        $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_hotfixes](machinename,datestamp,username,hotfixtype,hotfixid,installedon)`r`n" +
                        "VALUES ('$env:computername','$datestamp','$User','$tmp1','$tmp2','$tmp3')`r`n"
                        $SQLInsert = $SQLInsert + $InsertResults
                    }
                }
                Clear-Variable tmp1, tmp2, tmp3, InsertResults, hotfixcheck -ErrorAction SilentlyContinue    
            }
        }
        Clear-Variable x -ErrorAction SilentlyContinue

        #Writing SCCM Service Info to SQL
        if ($SCCMSVCRunning.length -eq 0){$SCCMSVCRunning="Not Installed"}
        $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_sccmclient](machinename,datestamp,username,sccmservicestatus,sccmclientversion)`r`n" +
        "VALUES ('$env:computername','$datestamp','$User','$SCCMSVCRunning','$SCCMClientVersion')`r`n"
        $SQLInsert = $SQLInsert + $InsertResults
        Clear-Variable InsertResults -ErrorAction SilentlyContinue


        #Writing Defender Status Info to SQL
        $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_defender](machinename,datestamp,username,AMProductVersion,AMEngineVersion,AMServiceEnabled,AntispywareEnabled,AntispywareSignatureLastUpdated,AntispywareSignatureVersion,AntivirusEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,NISEnabled,NISEngineVersion,NISSignatureLastUpdated,NISSignatureVersion,OnAccessProtectionEnabled,RealTimeProtectionEnabled)`r`n" +
        "VALUES ('$env:computername','$datestamp','$User','$AMProductVersion','$AMEngineVersion','$AMServiceEnabled','$AntispywareEnabled','$AntispywareSignatureLastUpdated','$AntispywareSignatureVersion','$AntivirusEnabled','$AntivirusSignatureLastUpdated','$AntivirusSignatureVersion','$NISEnabled','$NISEngineVersion','$NISSignatureLastUpdated','$NISSignatureVersion','$OnAccessProtectionEnabled','$RealTimeProtectionEnabled')`r`n"
        $SQLInsert = $SQLInsert + $InsertResults
        Clear-Variable InsertResults -ErrorAction SilentlyContinue

        #Writing IP Info to SQL
        $x=0
        for (;$x -le $AllIP.count - 1;$x++){
        
            $IP1 = [string]$ALLIP[$x][0]
            $IP2 = [string]$ALLIP[$x][1]
            $IP3 = [string]$ALLIP[$x][2]
            $IP4 = [string]$ALLIP[$x][3]
            $IP5 = [string]$ALLIP[$x][4]
            $IP6 = [string]$ALLIP[$x][5]
            $IP7 = [string]$ALLIP[$x][6]
            $IP8 = [string]$ALLIP[$x][7]
            $IP9 = [string]$ALLIP[$x][8]
            $IP10 = [string]$ALLIP[$x][9]
            $IP11 = [string]$ALLIP[$x][10]
            $IP12 = [string]$ALLIP[$x][11]
            $IP13 = [string]$ALLIP[$x][12]
            $IP14 = [string]$ALLIP[$x][13]
            
            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_IPConfiguration](machinename,datestamp,username,ConnectionType,RASEndpoint,DNSSuffixSearchList,InterfaceDescription,PhysicalAddress,DHCPEnabled,DHCPServer,DHCPLeaseObtained,DHCPLeaseExpires,IPAddress,SubnetMask,DefaultGateway,DNSServers,DHCPClassID)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$IP1','$IP2','$IP3','$IP4','$IP5','$IP6','$IP7','$IP8','$IP9','$IP10','$IP11','$IP12','$IP13','$IP14')`r`n"
            $SQLInsert = $SQLInsert + $InsertResults
            Clear-Variable IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8, IP9, IP10, IP12, IP13, IP14, InsertResults -ErrorAction SilentlyContinue
        }
        Clear-Variable x -ErrorAction SilentlyContinue

        #Writing ICMP Test results to SQL
        $x=0
        for (;$x -le $ICMPTest.count - 1;$x++){

            $IP1 = [string]$PingResults[$x][1]
            $IP2 = [string]$PingResults[$x][0]
            $IP3 = [string]$PingResults[$x][5]
            $IP4 = [string]$PingResults[$x][6]
            $IP5 = [string]$PingResults[$x][2]
            $IP6 = [string]$PingResults[$x][3]
            $IP7 = [string]$PingResults[$x][4]

            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_ICMPConnectivity](machinename,datestamp,username,DestinationServerName,DestinationServerIP,ConnectionResult,ICMPReplyLatency,InterfaceDescription,SourceIP,NextHop)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$IP1','$IP2','$IP3','$IP4','$IP5','$IP6','$IP7')`r`n"
            $SQLInsert = $SQLInsert + $InsertResults
            Clear-Variable IP1, IP2, IP3, IP4, IP5, IP6, IP7, InsertResults -ErrorAction SilentlyContinue
        }
        Clear-Variable x -ErrorAction SilentlyContinue

        #Writing DNS resolution results to SQL
        $x=0
        for (;$x -le $DNSLog.count - 1;$x++) {
            $IP1 = $DNSLog[$x][0]
            $IP2 = $DNSLog[$x][1]
            $IP3 = $DNSLog[$x][2]
            $IP4 = $DNSLog[$x][3]
            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_DNSResolution](machinename,datestamp,username,DestinationServerName,DestinationServerIP,NameAdministrator,SerialNumber)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$IP1','$IP2','$IP3','$IP4')`r`n"
            $SQLInsert = $SQLInsert + $InsertResults
            Clear-Variable IP1, IP2, IP3, IP4, InsertResults -ErrorAction SilentlyContinue
        }
        $x=0
        for (;$x -le $DNSExtLog.count - 1;$x++) {
            $IP1 = $DNSExtLog[$x][0]
            $IP2 = $DNSExtLog[$x][1]
            $IP3 = $DNSExtLog[$x][2]
            $IP4 = $DNSExtLog[$x][3]
            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_DNSResolution](machinename,datestamp,username,DestinationServerName,DestinationServerIP,NameAdministrator,SerialNumber)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$IP1','$IP2','$IP3','$IP4')`r`n"
            $SQLInsert = $SQLInsert + $InsertResults
            Clear-Variable IP1, IP2, IP3, IP4, InsertResults -ErrorAction SilentlyContinue
        }
        Clear-Variable x -ErrorAction SilentlyContinue

        #Writing Traceroute results to SQL
        $y=0
        for (;$y -le $TraceRouteOutput.count -1;$y++){
            $tmp = $TraceRouteOutput[$y].remoteaddress.IPAddressToString
            if ([string]::IsNullOrEmpty($tmp)) {
                $tmp1 = $TraceRouteOutput[$y].ComputerName
                $tmp2 = "Unable to Connect to host"
             } else {
                $tmp1 = $TraceRouteOutput[$y].ComputerName
                $tmp2 = [string]$TraceRouteOutput[$y].remoteaddress.IPAddressToString
                $tmp3 = [string]$TraceRouteOutput[$y].InterfaceDescription
                $tmp4 = [string]$TraceRouteOutput[$y].SourceAddress.IPAddress
                $tmp5 = [string]$TraceRouteOutput[$y].PingSucceeded
                $tmp6 = [string]$TraceRouteOutput[$y].PingReplyDetails.RoundtripTime
                $x=0
                for (;$x -le $TraceRouteOutput[$y].traceroute.count - 1;$x++) {
                    $tmp = [string]$TraceRouteOutput[$y].TraceRoute[$x]
                    if ($tmp -ne "0.0.0.0"){
                        $tmphops = $tmphops + $tmp + ","
                    }
                $tmp7 = $tmphops.Substring(0,$tmphops.Length-1)
                }
            }
            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_tracerouteresults](machinename,datestamp,username,DestinationServerName,DestinationServerIP,ConnectionResult,TraceRoutePath,ICMPReplyLatency,Interfacedescription,SourceIP)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$tmp1','$tmp2','$tmp5','$tmp7','$tmp6','$tmp3','$tmp4')`r`n"
            $SQLInsert = $SQLInsert + $InsertResults
            Clear-Variable tmp, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmphops, InsertResults -ErrorAction SilentlyContinue
        }

        #Writing internal web test results to SQL
        $x=0
        for (;$x -le $IntWebTest.count -1;$x++){
            $tmp1 = [string]$IntWebTest[$x].Computername
            $tmp2 = [string]$IntWebTest[$x].RemoteAddress.IPAddressToString
            If ($x -eq 0) {$tmp3 = "80"} else {$tmp3 = "443"}
            $tmp4 = [string]$IntWebTest[$x].TcpTestSucceeded

            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_internalwebconnectivity](machinename,datestamp,username,ServerName,ServerIPAddress,ConnectionResult,TCPPort)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$tmp1','$tmp2','$tmp4','$tmp3')`r`n"
            $SQLInsert = $SQLInsert + $InsertResults
            Clear-Variable tmp1, tmp2, tmp3, tmp4, InsertResults -ErrorAction SilentlyContinue
       }
       Clear-Variable x -ErrorAction SilentlyContinue

        #Writing external web test results to SQL
        if ($ExtWebChkErr.length -gt 0) {
            $tmp = [string]$ExtWebChkErr.message
            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_externalwebconnectivity](machinename,datestamp,username,ConnectionResult, ConnectionSpeed)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$tmp','')`r`n"
        } else {
            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_externalwebconnectivity](machinename,datestamp,username,ConnectionResult, ConnectionSpeed)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','Success','$WebSpeedCheck')`r`n"
        }
        $SQLInsert = $SQLInsert + $InsertResults
        Clear-Variable tmp, InsertResults -ErrorAction SilentlyContinue

        #Writing FileShare test results to SQL
        $x=0
        for (;$x -le 2;$x++){
            $tmp1 = $FileConnectivityTest[$x][0]
            $tmp2 = $FileConnectivityTest[$x][1]
            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_FileShareConnectivity](machinename,datestamp,username,FileShareName,ConnectionResult)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$tmp1','$tmp2')`r`n"
            $SQLInsert = $SQLInsert + $InsertResults
            Clear-Variable tmp1, tmp2, InsertResults -ErrorAction SilentlyContinue
        }
        Clear-Variable x -ErrorAction SilentlyContinue

        #Writing individual proxy test results to SQL
        $x=0
        For (;$x -le $Proxytestlog.count -1;$x++){
            $tmp1 = $Proxytestlog[$x][0]
            $tmp2 = $Proxytestlog[$x][1]
            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_ProxyTesting](machinename,datestamp,username,ProxyAddress, ProxyConnectionResult)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$tmp1','$tmp2')`r`n"
            $SQLInsert = $SQLInsert + $InsertResults
            Clear-Variable tmp1, tmp2, InsertResults -ErrorAction SilentlyContinue
        }
        Clear-Variable x -ErrorAction SilentlyContinue

        for ($y=0;$y -le $RoutePrint.count -1;$y++) {
            $temp1 = $RoutePrint[$y][0]
            $temp2 = $RoutePrint[$y][1]
            $temp3 = $RoutePrint[$y][2]
            $temp4 = $RoutePrint[$y][3]
            $InsertResults = "INSERT INTO [csidb].[dbo].[tbl_IPRouteTable](machinename,datestamp,username,NetworkDestination,NetMask,Gateway,Metric)`r`n" +
            "VALUES ('$env:computername','$datestamp','$User','$temp1','$temp2','$temp3','$temp4')`r`n"
            $SQLInsert = $SQLInsert + $InsertResults
            Clear-Variable tmp1, tmp2, tmp3, tmp4, InsertResults -ErrorAction SilentlyContinue
        }
        Clear-Variable y -ErrorAction SilentlyContinue

        Invoke-sqlcmd -Query $SQLInsert
        $sqlConnection.Close()
    }

    ################################

    # Writing All Data to Log File #

    ################################

    $DiskInfo = ""
    $tmp = $MachineInformation[5]
    foreach ($Vol in $tmp){
        $tmp1 = [string]$vol[1]+"GB"
        $tmp2 = [string]$Vol[2]+"GB"
        $DiskInfo = $DiskInfo + "Disk, Size, Free Space                                                 " + $Vol[0] + ", " + $tmp1 + ", " + $tmp2 + "`r`n"
    }

If ($RASConnection.length -gt 0){$ConnectionType = $RASConnection}

$Title = @"
--------------------------------------- 
- Client Support Information Log File -
---------------------------------------
"@

    write-output $Title | out-file $LogFileName

$logfileinfo = @"

$Datestamp

Logged on User:                                                        $User ($env:username)

Computer name:                                                         $env:computername

Domain:                                                                $DomainName

Logon Server:                                                          $LogonServerName ($LogonServerLocation)

GPO Server:                                                            $GPOAppliedfrom

GPOs last applied:                                                     $GPOAppliedDate $GPOAppliedTime

PC Model:                                                              $PCModel ($BIOSVersion)

Windows Version:                                                       $OSVersion ($WindowsReleaseVersion)

$DiskInfo
Connection Type:                                                       $ConnectionType

NTP Server:                                                            $NTPSource

NTP last sync:                                                         $SyncTime
    
-------------------
- Testing Summary -
-------------------

Windows updates installed in the last 60 days:                         $HotfixInstallSummary

Windows Defender status:                                               $DefenderAVSummary

Windows Defender last update:                                          $AntivirusSignatureLastUpdated

SCCM Client installed:                                                 $SCCMSVCSummary

Connection to the datacentres:                                         $Pingtestsummary

Internal DNS Resolution:                                               $DNSTestSummary

External DNS Resolution:                                               $DNSExtTestSummary

DNS Server Connection:                                                 $IntDNSTestSummary
Connection to internal Web server:                                     $InternalWebTestSummary

Connection to internet web server:                                     $ExternalWebtestSummary

Connection to Windows File Share in the datacentre:                    $FileShareTestSummary

------------------------------------------------
- Device configuration and test result details -
------------------------------------------------

--------------------------
- Group Policies Applied -
--------------------------

User OU:              $UserOU

Computer OU:          $ComputerOU

GPO Server:           $GPOAppliedfrom

GPOs Last Applied:    $GPOAppliedDate $GPOAppliedTime

GPOs Applied:

$AllAppliedGPOs
--------------------------------------
- Recently Installed Windows Updates -
--------------------------------------

$HotFixesInstalled
-------------------------------------------
- Windows Defender Status and Information -
-------------------------------------------

$DefenderAllInfo

--------------------------------------------------------
- Microsoft SCCM Client Service Status and Information -
--------------------------------------------------------

SCCM Client Status:   $SCCMSVCRunning

SCCM Client Version:  $SCCMClientVersion

--------------------
- IP Configuration -
--------------------
$DisplayIPInfo
Route Table

Destination Address          Destination Subnet Mask        Gateway Address                Interface Metric

$IPRouteInfo
-----------------------------
- Testing ICMP connectivity -
-----------------------------

Pinging DCs in both datacentres and local GW (when on LAN)
$PingLog
--------------------------
- Testing DNS Resolution -
--------------------------

Testing connectivity to the InfoBlox servers:
$DNSSvrTestLog
Resolving internal Federation DNS entry, Domain Controllers in both datacentres as well as Microsoft.co.uk

Destination Hostname           Resolved IP Address            Name Administrator             Serial Number

$dnsreslog
Resolving external Federation DNS entry

Destination Hostname           Resolved IP Address            Name Administrator             Serial Number

$DNSExtResLog

----------------------
- TraceRoute Testing -
----------------------

Running a TraceRoute to the Domain Controllers in both datacentres
$TraceRouteLog

-------------------------------------
- Testing Internal Web connectivity -
-------------------------------------

Testing connection on TCP80 and TCP443 to internal web server

$InternalWebTestLog
-------------------------------------
- Testing External Web connectivity -
-------------------------------------

Downloading a 10MB test file from the Internet to check connectivity and bandwidth

An average of 6Mbs - 10Mbs is expected, regardless of connection type

$ExternalWebTestLog
-----------------------------------------
- Testing Individual Proxy connectivity -
-----------------------------------------

Testing that all virtual IPs on the F5s are listening on port 8080 in both datacentres

$VIPtesting
Testing connectivity through each individual proxy

$IndividualProxytestlog
-------------------------------------------
- Testing Windows file share connectivity -
-------------------------------------------

Connecting to the Netlogon share on domain controllers in both datacentres

$FileConnectivityLog
Testing connectivity speed by copying a 50MB file from the workstation to the storage in the datacentre

On a LAN (puple cable) connection, 70Mbps - 80Mps is average, on a RAS connection, 15Mbp - 20Mbs is expected

$FileSpeedCheck

---------------------
- Group Memberships -
---------------------

Group Memberships:
$AllGroupMemberships
"@

    Add-Content $LogFileName $logfileinfo

    #Uploading log file to Teams Site

    $Folder = "$env:userprofile\downloads"
    $DocLibName = "Documents"

    Add-Type -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.dll"
    Add-Type -Path "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.Runtime.dll"

    $LoopNum = 1
    $OneDriveError = 0
    Clear-Variable -name UploadError -ErrorAction SilentlyContinue
    for (;$LoopNum -le 5;$LoopNum++) {
        Clear-Variable Context, Creds, List, OneDriveError, UploadError -ErrorAction SilentlyContinue
        Write-Progress -Activity "Uploading log file - Attempt $LoopNum" -Status "99% Complete:" -PercentComplete 99
        $error.Clear()
        $Context = New-Object Microsoft.SharePoint.Client.ClientContext($SiteURL)
        $Creds = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($User,$Password)
        $Context.Credentials = $Creds
        $List = $Context.Web.Lists.GetByTitle("$DocLibName")
        $Context.Load($List)
        $Context.Load($List.RootFolder)
        $error.Clear()

        Try {
            $Context.ExecuteQuery()
            $OneDriveError = "0"
            $UploadError = ""
        } catch {
            $UploadError = $Error
            $OneDriveError = "1"
        }
        if ($OneDriveError -eq 0) {
            Clear-Variable -name UploadError -ErrorAction SilentlyContinue
            break
        }
    }

    if ($OneDriveError -eq 0) {
        $ServerRelativeUrlOfRootFolder = $List.RootFolder.ServerRelativeUrl
        $uploadFolderUrl = $ServerRelativeUrlOfRootFolder+"/"+$foldername
        Foreach ($File in (dir $Folder -File))
        {
            $fntemp = $file.Name
            if ($fntemp.startswith($env:computername))
            {
                $FileStream = New-Object IO.FileStream($File.FullName,[System.IO.FileMode]::Open)
                $FileCreationInfo = New-Object Microsoft.SharePoint.Client.FileCreationInformation
                $FileCreationInfo.Overwrite = $true
                $FileCreationInfo.ContentStream = $FileStream
                $FileCreationInfo.URL = $File
                if($foldername -eq $null)
                {
                  $Upload = $List.RootFolder.Files.Add($FileCreationInfo)
                }
                  Else
                {
                   $targetFolder = $Context.Web.GetFolderByServerRelativeUrl($uploadFolderUrl)
                   $Upload = $targetFolder.Files.Add($FileCreationInfo);
                }
                $Context.Load($Upload)
                $Context.ExecuteQuery()
            }
        }
        $wshell.Popup("The Client Support Information script has successfully run",0," Client Support Information",0x0)
    } else {
        $wshell.Popup("The Client Support Information script has successfully run, but could not connect to SharePoint to upload the log file",0," Client Support Information",0x0)

$logfileinfo = @"
----------------------------
- Logfile Upload Error Log -
----------------------------

The following errors were found whilst trying to upload the log file:

$UploadError
"@
        Add-Content $LogFileName $logfileinfo
        Start-Process "c:\windows\system32\notepad.exe" $LogFileName
    }

} 

