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
if(Get-WindowsFeature web-default-doc, web-dir-browsing, web-http-errors, web-static-content, web-http-logging, web-stat-compression, web-filtering, web-mgmt-console,web-metabase)
{
    Write-Host "Installing windows features for DSC"
    $ChangeNeeded = Add-windowsFeature web-default-doc, web-dir-browsing, web-http-errors, web-static-content, web-http-logging, web-stat-compression, web-filtering, web-mgmt-console,web-metabase -IncludeAllSubFeature -IncludeManagementTools
    if($ChangeNeeded.RestartNeeded -eq "Yes" -and $ChangeNeeded.Success)
    {
        Write-Host "Do not need to Reset IIS"
    }Else
    {
        Write-Host "Added features restarting IIS"
        invoke-expression -command "iisreset"
    }
}Else
{
    Write-Host "Windows features for DSC are already installed"
}
# Configure firewall to allow port 8080
if(!(Get-NetFirewallRule -DisplayName "Port 8080 inbound" -ErrorAction SilentlyContinue))
{
    Write-Host "Creating firewall rule `'Port 8080 inbound`' to allow access to DSC service"
    New-NetFirewallRule -DisplayName "Port 8080 inbound" -Action Allow -Direction Inbound -Protocol TCP -LocalPort 8080
}Else
{
    Write-Host "Already created firewall rule `'Port 8080 inbound`'" 
}

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
$Pfx = $CertPath + "\DSC.pfx"
#$SolutionFolder = $DSCConfigurationPath + "\Solutions"
$pwd = ConvertTo-SecureString -String "P@ssword1" -Force -AsPlainText

#Verify folders are created

New-Item $DSCModulePath -ItemType directory -ErrorAction SilentlyContinue
New-Item $DSCConfigurationPath -ItemType directory -ErrorAction SilentlyContinue
New-Item $PullserverPath -ItemType directory -ErrorAction SilentlyContinue
New-Item $CertPath -ItemType directory -ErrorAction SilentlyContinue
#New-Item $SolutionFolder -ItemType directory -ErrorAction SilentlyContinue

#Create or verify that Cert is in place
if((Get-ChildItem "Cert:\LocalMachine\My" | ?{$_.Subject -eq $DSCEndPointSubjectName} | Select-object -First 1).Subject -eq $DSCEndPointSubjectName)
{
    Write-Host "DSC Service certificate already exists"
    $DSCAcceptSelfSignedCertificates = $data.NonNodeData.DSCConfig.DSCAcceptSelfSignedCertificates
}Else
{
    Write-Host "DSC Service certificate doesn't exist, creating a self-signed certificate"
    $DSCAcceptSelfSignedCertificates = $true
    New-SelfSignedCertificate -DnsName $DSCEndPointName -CertStoreLocation cert:\LocalMachine\My
    Get-ChildItem "Cert:\LocalMachine\My" | where {$_.Subject -eq $DSCEndPointSubjectName} | Select-object -First 1 | Export-PfxCertificate -FilePath $Pfx -Password $pwd
}

if($data.NonNodeData.DSCConfig.DSCAcceptSelfSignedCertificates)
{
    #    Import-PfxCertificate -FilePath "$CertPath\DSC.pfx" -CertStoreLocation Cert:\LocalMachine\AuthRoot -Password $Pwd
    If(!(Get-ChildItem -Path Cert:\localmachine\AuthRoot | where{$_.Subject -eq $DSCEndPointSubjectName} | Test-Certificate -dnsname $DSCEndPointName))
    {
        Write-Host "DSC Service certificate is self-signed and untrusted, import to LocalMachine\AuthRoot"
        Import-PfxCertificate -FilePath $Pfx -CertStoreLocation Cert:\LocalMachine\AuthRoot -Password $Pwd
    }Else
    {
        Write-Host "DSC Service certificate is self-signed and it's trusted, no action"
    }
}

if($data.NonNodeData.DSCConfig.DSCConfigModuleOnline)
{    
    $data.NonNodeData.DSCConfig.InstalledModules | foreach-object {
        If(Get-InstalledModule -Name $_ -ea SilentlyContinue)
        {
            if((Get-InstalledModule -Name $_ -ea SilentlyContinue).Version.CompareTo((Find-Module -Name $_ -Repository PSGallery).Version) -ne 0)
            {
                Write-Host "Updating module " $_
                Uninstall-Module -Name $_ -AllVersions -Force
                Find-Module -Name $_ -Repository PSGallery | Install-Module -Verbose
                            <#
            $ModuleName = $_
            $ModuleFolder = "$env:ProgramFiles\WindowsPowerShell\Modules\$ModuleName"
            $ModuleVersion = (Get-ChildItem $ModuleFolder).Name
            $WorkingDirectory = "$env:TEMP\$ModuleName"
            New-Item $WorkingDirectory -ItemType Directory -ea SilentlyContinue -Force
            Get-ChildItem "$ModuleFolder\$ModuleVersion" | Copy-Item -Destination $WorkingDirectory -Recurse
            Publish-ModuleToPullServer -Name $ModuleName -Version $ModuleVersion -PullServerWebConfig $DSCWebConfigFile -ModuleBase $WorkingDirectory
            Remove-item $WorkingDirectory -recurse
            #>
            }Else
            {
                Write-Host "Module " $_ " is installed and up to date"
            }
        }Else
        {
            Write-Host "Installing module " $_
            Find-Module -Name $_ -Repository PSGallery | Install-Module -Verbose
            <#
            $ModuleName = $_
            $ModuleFolder = "$env:ProgramFiles\WindowsPowerShell\Modules\$ModuleName"
            $ModuleVersion = (Get-ChildItem $ModuleFolder).Name
            $WorkingDirectory = "$env:TEMP\$ModuleName"
            New-Item $WorkingDirectory -ItemType Directory -ea SilentlyContinue -Force
            Get-ChildItem "$ModuleFolder\$ModuleVersion" | Copy-Item -Destination $WorkingDirectory -Recurse
            Publish-ModuleToPullServer -Name $ModuleName -Version $ModuleVersion -PullServerWebConfig $DSCWebConfigFile -ModuleBase $WorkingDirectory
            Remove-item $WorkingDirectory -recurse
            #>
        }
    }
   # Start-Sleep -Seconds 5
}Else
{
    Write-Host "WARNING: You have said that this server doesn't have internet access so we are unable to get current versions of modules." -ForegroundColor Red
    Write-Host "Download and install the following modules " $data.NonNodeData.DSCConfig.InstalledModules
    Exit
}

if(!((Get-DSCConfiguration -ErrorAction SilentlyContinue).ConfigurationName | where {$_ -ne "DSC_PullServer_Config"}))
{
    Write-host "Starting DSC Configuration on local machine"
    $DSCCertThumbprint = (Get-ChildItem "Cert:\LocalMachine\My" | where {$_.Subject -eq $DSCEndPointSubjectName} | Select-object -First 1).Thumbprint     #$data.NonNodeData.DSCConfig.DSCCertThumbprint
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
}Else
{
    Write-Host "DSC Server is already configured..."
}

# Get the path and file for Sites web.config
$SiteName = (($data.NonNodeData.DSCConfig.DSCConfigServiceEndPoint).split("/")[2]).split(":")[0]
$DSCWebConfigFile = (Get-WebConfigFile "IIS:\Sites\$SiteName").FullName

$data.NonNodeData.DSCConfig.InstalledModules | ForEach-Object {
    $ModuleName = $_
    $ModuleFolder = "$env:ProgramFiles\WindowsPowerShell\Modules\$ModuleName"
    $ModuleVersion = (Get-ChildItem $ModuleFolder).Name
    if(!(Get-Item "$DSCModulePath\$ModuleName`_$ModuleVersion.zip" -ea SilentlyContinue))
    {
        Write-Host "Cannot find compressed file for $ModuleName with version $ModuleVersion"
        $WorkingDirectory = "$env:TEMP\$ModuleName"
        New-Item $WorkingDirectory -ItemType Directory -ea SilentlyContinue -Force
        Get-ChildItem "$ModuleFolder\$ModuleVersion" | Copy-Item -Destination $WorkingDirectory -Recurse
        Publish-ModuleToPullServer -Name $ModuleName -Version $ModuleVersion -PullServerWebConfig $DSCWebConfigFile -ModuleBase $WorkingDirectory
        Remove-item $WorkingDirectory -recurse
    }Else
    {
        Write-Host "Found compressed file for $ModuleName with version $ModuleVersion"
    }
}
Write-Host "Updating checksum on all compressed modules in $DSCModulePath"
New-DscChecksum -Path $DSCModulePath -Force