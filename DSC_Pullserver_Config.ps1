#***************************************************************************************
# This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
# THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED 
# TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS for A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free right to use and modify 
# the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or 
# trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in 
# which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, 
# including attorneys fees, that arise or result from the use or distribution of the Sample Code.
#
# This script generates PullServer configuration, starts DSC feature, installs modules (If server has internet access), creates self signed cert and export root Ca 
# (if you are using self signed cert), deploys IIS and creates DSC website/Web service,creates firewall rule, then runs Start-DscConfiguration on localmachine
#
# -Run this script as a local server Administrator
# -Run this script from elevaed prompt
# 
# Don't forget to: Set-ExecutionPolicy RemoteSigned
#
# Written by Chris Weaver (christwe@microsoft.com)
#
#****************************************************************************************

# https://github.com/PowerShell/xPSDesiredStateConfiguration

param(
        [string][Parameter(Mandatory=$true)] $ConfigDataFile = 'DSCConfigData.psd1',
        [string][Parameter(Mandatory=$true)] $ConfigFile = 'DSCConfig.ps1'
)
<#
$ObjModule = Get-Module xPSDesiredStateConfiguration

if($ObjModule -le 0)
{
    Install-PackageProvider -Name Nuget -Force -RequiredVersion "2.8.5.201" -Confirm:$false
    Set-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2/ -InstallationPolicy Trusted
    Install-Module xPSDesiredStateConfiguration
}
#>
$ConfigData = "$PSScriptRoot\$ConfigDataFile"

#Load the Data File to get the Accounts
$data = Invoke-Expression (Get-Content $ConfigData | out-string)
    
# Need to install IIS 2012 R2
import-module servermanager

#Add-WindowsFeature -Name Web-Common-Http,Web-Asp-Net,Web-Net-Ext,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Http-Logging,Web-Request-Monitor,Web-Basic-Auth,Web-Windows-Auth,Web-Filtering,Web-Performance,Web-Mgmt-Console,Web-Mgmt-Compat,RSAT-Web-Server,WAS
Add-windowsFeature web-default-doc, web-dir-browsing, web-http-errors, web-static-content, web-http-logging, web-stat-compression, web-filtering, web-mgmt-console,web-metabase -IncludeAllSubFeature -IncludeManagementTools
invoke-expression -command "iisreset"

# Configure firewall to allow port 8080
New-NetFirewallRule -DisplayName "Port 8080 inbound" -Action Allow -Direction Inbound -Protocol TCP -LocalPort 8080

$DSCPhysicalPath = $data.NonNodeData.DSCConfig.DSCServicePhysicalPath
$DSCModulePath = $data.NonNodeData.DSCConfig.DSCConfigPath + "\Modules"
$DSCConfigurationPath = $data.NonNodeData.DSCConfig.DSCConfigPath + "\Configurations"
$DSCEndPointName = (($data.NonNodeData.DSCConfig.DSCConfigServiceEndPoint).split("/")[2]).split(":")[0]      # Pull the EndpointName out of url
$DSCEndPointSubjectName = "CN=" + (($data.NonNodeData.DSCConfig.DSCConfigServiceEndPoint).split("/")[2]).split(":")[0]
$DSCUseSecurityBestPractices = $data.NonNodeData.DSCConfig.DSCUseSecurityBestPractices
$DSCRegistryKey = $data.NonNodeData.DSCConfig.DSCConfigRegistryKey
$DSCRegistryKeyPath = $data.NonNodeData.DSCConfig.DSCConfigRegistryKeyFile
$PullserverPath = $DSCConfigurationPath + "\Pullserver"
$CertPath = $DSCConfigurationPath + "\Cert"

#Verify folders are created

New-Item $DSCModulePath -ItemType directory -ErrorAction SilentlyContinue
New-Item $DSCConfigurationPath -ItemType directory -ErrorAction SilentlyContinue
New-Item $PullserverPath -ItemType directory -ErrorAction SilentlyContinue
New-Item $CertPath -ItemType directory -ErrorAction SilentlyContinue

#Create or verify that Cert is in place
if((Get-ChildItem "Cert:\LocalMachine\My" | ?{$_.Subject -eq $DSCEndPointSubjectName} | Select-object -First 1).Subject -eq $DSCEndPointSubjectName)
{
    $DSCAcceptSelfSignedCertificates = $data.NonNodeData.DSCConfig.DSCAcceptSelfSignedCertificates
}Else
{
    $DSCAcceptSelfSignedCertificates = $true
    New-SelfSignedCertificate -DnsName $DSCEndPointName -CertStoreLocation cert:\LocalMachine\My
    $pwd = ConvertTo-SecureString -String "P@ssword1" -Force -AsPlainText
    
    New-Item $CertPath -ItemType directory -ErrorAction SilentlyContinue
    Get-ChildItem "Cert:\LocalMachine\My" | where {$_.Subject -eq $DSCEndPointSubjectName} | Select-object -First 1 | Export-PfxCertificate -FilePath "$CertPath\DSC.pfx" -Password $pwd
}
$DSCCertThumbprint = (Get-ChildItem "Cert:\LocalMachine\My" | where {$_.Subject -eq $DSCEndPointSubjectName} | Select-object -First 1).Thumbprint     #$data.NonNodeData.DSCConfig.DSCCertThumbprint

if($data.NonNodeData.DSCConfig.DSCConfigModuleOnline)
{
    $SourceModulePath = "$env:ProgramFiles\WindowsPowerShell\DscService\Modules\*"
    #Install-PackageProvider -Name Nuget -Force -RequiredVersion "2.8.5.201" -Confirm:$false
    #Set-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2/ -InstallationPolicy Trusted
    
    $data.NonNodeData.DSCConfig.InstalledModules | foreach-object {
        Install-Module -Name $_ -Force
    }
    Start-Sleep -Seconds 30
}Else
{
    Write-Host "WARNING: You have said that this server doesn't have internet access so we are unable to get current versions of modules." -ForegroundColor Red
    Write-Host "Download and install the following modules SharePointDSC, xWebAdministration, xCredSSP, xDiagnostics, and XPSDesiredStateConfiguration"
    Exit
}

. "$PSScriptRoot\$ConfigFile"

configuration DSC_PullServer_Config
{ 
    Param (
        [string]$NodeName = 'localhost',
        [string][Parameter(Mandatory=$true)]$PhysicalPath,
        [string][Parameter(Mandatory=$true)]$CertThumbprint,
        [string][Parameter(Mandatory=$true)]$ModulePath,
        [string][Parameter(Mandatory=$true)]$ConfigurationPath,
        [string][Parameter(Mandatory=$true)]$EndPointName,
        [boolean][Parameter(Mandatory=$true)]$UseSecurityBestPractices,
        [boolean][Parameter(Mandatory=$true)]$AcceptSelfSignedCertificates,
        [string][Parameter(Mandatory=$true)]$RegistryKey,
        [string][Parameter(Mandatory=$true)]$RegistryKeyPath
    )

	Import-DSCResource -ModuleName xPSDesiredStateConfiguration
    Import-DSCResource -ModuleName PSDesiredStateConfiguration
		 
	Node $NodeName 
    { 
	    WindowsFeature DSCServiceFeature 
		{ 
		    Ensure = 'Present'
		    Name   = 'DSC-Service'             
	    } 
       
		xDscWebService PSDSCPullServer 
        { 
		    Ensure                   = 'Present' 
		    EndpointName             = $EndPointName
		    Port                     = 8080 
		    PhysicalPath             = $PhysicalPath
		    CertificateThumbPrint    = $CertThumbprint
		    ModulePath               = $ModulePath
		    ConfigurationPath        = $ConfigurationPath 
		    State                    = 'Started'
		    DependsOn                = '[WindowsFeature]DSCServiceFeature'     
		    UseSecurityBestPractices = $UseSecurityBestPractices
            AcceptSelfSignedCertificates = $AcceptSelfSignedCertificates
            RegistrationKeyPath = $RegistryKeyPath
        } 

        File RegistrationKeyFile
        {
            Ensure          = 'Present'
            Type            = 'File'
            DestinationPath = $RegistryKeyPath + "\RegistrationKeys.txt"
            Contents        = $RegistryKey
        }
    }
}

DSC_PullServer_Config -PhysicalPath $DSCPhysicalPath -CertThumbprint $DSCCertThumbprint -ModulePath $DSCModulePath -ConfigurationPath $DSCConfigurationPath -EndPointName $DSCEndPointName -UseSecurityBestPractices $DSCUseSecurityBestPractices -AcceptSelfSignedCertificates $DSCAcceptSelfSignedCertificates -RegistryKey $DSCRegistryKey -RegistryKeyPath $DSCRegistryKeyPath -OutputPath $PullserverPath
Start-DscConfiguration -Path $PullserverPath -Wait -Verbose -Force

# Get the path and file for Sites web.config
$SiteName = (($data.NonNodeData.DSCConfig.DSCConfigServiceEndPoint).split("/")[2]).split(":")[0]
$DSCWebConfigFile = (Get-WebConfigFile "IIS:\Sites\$SiteName").FullName

# Create packages for modules so that servers can grab them if they need them 
$data.NonNodeData.DSCConfig.InstalledModules | ForEach-Object{
    $ModuleName = $_
    $ModuleFolder = "$env:ProgramFiles\WindowsPowerShell\Modules\$ModuleName"
    $ModuleVersion = (Get-ChildItem $ModuleFolder).Name
    $WorkingDirectory = "$env:TEMP\$ModuleName"
    New-Item $WorkingDirectory -ItemType Directory -ea SilentlyContinue -Force
    Get-ChildItem "$ModuleFolder\$ModuleVersion" | Copy-Item -Destination $WorkingDirectory -Recurse
    Publish-ModuleToPullServer -Name $ModuleName -Version $ModuleVersion -PullServerWebConfig $DSCWebConfigFile -ModuleBase $WorkingDirectory
    Remove-item $WorkingDirectory -recurse
}