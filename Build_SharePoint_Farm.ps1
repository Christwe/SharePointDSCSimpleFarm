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

New-Item "..\Logs" -ItemType directory -ErrorAction SilentlyContinue

Start-Transcript -Path "..\logs\DSC_SharePoint_Transaction.log" -Append -IncludeInvocationHeader

Get-Date

$ObjModule = Get-Module xPSDesiredStateConfiguration

if($ObjModule.count -le 0)
{
    Install-PackageProvider -Name Nuget -Force -RequiredVersion "2.8.5.201" -Confirm:$false
    Set-PSRepository -Name PSGallery -SourceLocation https://www.powershellgallery.com/api/v2/ -InstallationPolicy Trusted
    Install-Module xPSDesiredStateConfiguration
}

if(((Get-DSCConfiguration).ConfigurationName | Select-Object -First 1) -ne "DSC_PullServer_Config")
{
    Write-Host "Configure DSC Server..."
    .\DSC_Pullserver_Config.ps1 -ConfigDataFile $ConfigDataFile -ConfigFile $ConfigFile 
}Else
{
    Write-Host "DSC Server is already configured..."
}
Write-Host "Generating MOF files for SharePoint servers..."
.\DSC_Generate_MOFFiles.ps1 -ConfigDataFile $ConfigDataFile -ConfigFile $ConfigFile
Write-Host "Setup DSCLocalConfiguration manager on all nodes..."
.\DSC_Client_Config.ps1 -ConfigDataFile $ConfigDataFile -ConfigFile $ConfigFile
Write-Host "Sit back, drink your coffee and watch the SharePoint farm get built." -ForegroundColor Green

Get-Date

Stop-Transcript