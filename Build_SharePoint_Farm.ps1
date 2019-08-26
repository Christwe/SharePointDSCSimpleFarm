#***************************************************************************************
# This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
# THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED 
# TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS for A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free right to use and modify 
# the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or 
# trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in 
# which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, 
# including attorneys fees, that arise or result from the use or distribution of the Sample Code.
#
# Using other scripts, this script will initiaite the starting of DSC and build out of SharePoint farm, I have tested the 
# following configurations:
#      - MultiServer farm SP2016
#      - Single Server farm SP2016
#
# -Run this script as a local server Administrator
# -Run this script from elevaed prompt
# 
# Don't forget to: Set-ExecutionPolicy RemoteSigned
#
# Written by Chris Weaver (christwe@microsoft.com)
#
#****************************************************************************************

param(
        [string][Parameter(Mandatory=$true)] $ConfigDataFile,
        [string][Parameter(Mandatory=$true)] $ConfigFile
)

Function New-Logfile
{
	param([String]$LogPath = "C:\Script", [string]$PreFix = "ScriptOutput")
	$d = Get-Date
	$Day = $d.Day
	$Month = $d.Month
	$Year = $d.Year
	$Hour = $d.Hour
	$Min = $d.Minute
	$Sec = $d.Second
	
	if(!(Test-Path -Path $LogPath -PathType Container))
	{
		New-Item -Path $LogPath -ItemType Directory | Out-Null
	}
	$FileName = New-Item -Path "$LogPath\$PreFix$Day$Month$Year$Hour$Min$Sec.log" -ItemType File -Force
	return $FileName.FullName
}

New-Item "..\Logs" -ItemType directory -ErrorAction SilentlyContinue

$LogFile = New-LogFile -LogPath "..\Logs" -PreFix "DSC_SP_Build"

Start-Transcript -Path $LogFile -Append -IncludeInvocationHeader

Get-Date

#$SiteName = (($data.NonNodeData.DSCConfig.DSCConfigServiceEndPoint).split("/")[2]).split(":")[0]
#$DSCWebConfigFile = (Get-WebConfigFile "IIS:\Sites\$SiteName").FullName

#   Write-Progress "Reviewing config files for any prereqs that are required"
# Need to add prereqs that admins need to complete
if(!(Get-PackageProvider -Name Nuget -ListAvailable -ErrorAction SilentlyContinue))
{
    Write-Host "Installing Nuget package"
    Install-PackageProvider -Name Nuget -Force -RequiredVersion "2.8.5.201" -Confirm:$false -Verbose
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -Verbose
}Else
{
    Write-host "Nuget package already installed"
}

If(Get-InstalledModule -Name xPSDesiredStateConfiguration -ea SilentlyContinue)
{
    if((Get-InstalledModule -Name xPSDesiredStateConfiguration -ea SilentlyContinue).Version.CompareTo((Find-Module -Name xPSDesiredStateConfiguration -Repository PSGallery).Version) -ne 0)
    {
        Write-Host "Updating module xPSDesiredStateConfiguration"
        Uninstall-Module -Name xPSDesiredStateConfiguration -AllVersions -Force -Verbose
        Find-Module -Name xPSDesiredStateConfiguration -Repository PSGallery | Install-Module -Verbose
       <# $ModuleFolder = "$env:ProgramFiles\WindowsPowerShell\Modules\xPSDesiredStateConfiguration"
        $ModuleVersion = (Get-ChildItem $ModuleFolder).Name
        $WorkingDirectory = "$env:TEMP\xPSDesiredStateConfiguration"
        New-Item $WorkingDirectory -ItemType Directory -ea SilentlyContinue -Force
        Get-ChildItem "$ModuleFolder\$ModuleVersion" | Copy-Item -Destination $WorkingDirectory -Recurse
        Publish-ModuleToPullServer -Name "xPSDesiredStateConfiguration" -Version $ModuleVersion -PullServerWebConfig $DSCWebConfigFile -ModuleBase $WorkingDirectory
        Remove-item $WorkingDirectory -recurse
        #>
    }Else
    {
        Write-Host "Module xPSDesiredStateConfiguration is installed and update is available"
    }
}Else
{
    Write-Host "Installing module xPSDesiredStateConfiguration"
    Find-Module -Name xPSDesiredStateConfiguration -Repository PSGallery | Install-Module -Verbose
   <# $ModuleFolder = "$env:ProgramFiles\WindowsPowerShell\Modules\xPSDesiredStateConfiguration"
    $ModuleVersion = (Get-ChildItem $ModuleFolder).Name
    $WorkingDirectory = "$env:TEMP\xPSDesiredStateConfiguration"
    New-Item $WorkingDirectory -ItemType Directory -ea SilentlyContinue -Force
    Get-ChildItem "$ModuleFolder\$ModuleVersion" | Copy-Item -Destination $WorkingDirectory -Recurse
    Publish-ModuleToPullServer -Name "xPSDesiredStateConfiguration" -Version $ModuleVersion -PullServerWebConfig $DSCWebConfigFile -ModuleBase $WorkingDirectory
    Remove-item $WorkingDirectory -recurse
    #>
}

Write-Host "Configure DSC Server..."
.\DSC_Pullserver_Config.ps1 -ConfigDataFile $ConfigDataFile -ConfigFile $ConfigFile
Write-Host "Generating MOF files for SharePoint servers..."
.\DSC_Generate_MOFFiles.ps1 -ConfigDataFile $ConfigDataFile -ConfigFile $ConfigFile
Write-Host "Setup DSCLocalConfiguration manager on all nodes..."
.\DSC_Client_Config.ps1 -ConfigDataFile $ConfigDataFile -ConfigFile $ConfigFile
Write-Host "Sit back, drink your coffee and watch the SharePoint farm get built." -ForegroundColor Green

Get-Date

Stop-Transcript