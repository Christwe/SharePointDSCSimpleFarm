#***************************************************************************************
# This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
# THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED 
# TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS for A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free right to use and modify 
# the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or 
# trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in 
# which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, 
# including attorneys fees, that arise or result from the use or distribution of the Sample Code.
#
# This script collects username and passwords for service accounts then generates MOF files for DSC
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
        [string][Parameter(Mandatory=$true)] $ConfigDataFile = 'DSCConfigData.psd1',
        [string][Parameter(Mandatory=$true)] $ConfigFile = 'DSCConfig.ps1'
)

#https://gallery.technet.microsoft.com/scriptcenter/Test-Credential-dda902c6
Function Test-Credential {
    [OutputType([Bool])]
    
    Param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeLine = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias(
            'PSCredential'
        )]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter()]
        [String]
        $Domain = $Credential.GetNetworkCredential().Domain
    )

    Begin {
        [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.AccountManagement") |
            Out-Null

        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
            [System.DirectoryServices.AccountManagement.ContextType]::Domain, $Domain
        )
    }

    Process {
        foreach ($item in $Credential) {
            $networkCredential = $Credential.GetNetworkCredential()
            
            Write-Output -InputObject $(
                $principalContext.ValidateCredentials(
                    $networkCredential.UserName, $networkCredential.Password
                )
            )
        }
    }

    End {
        $principalContext.Dispose()
    }
}

. "$PSScriptRoot\$ConfigFile"

$ConfigData = "$PSScriptRoot\$ConfigDataFile"

#Load the Data File to get the Accounts
$data = Invoke-Expression (Get-Content $ConfigData | out-string)
$dscConfigPath = $data.NonNodeData.DSCConfig.DSCConfigPath + "\Configurations"

#Delete all mof and checksum files as we will create new ones
Write-Host "Removing all configurations files from $dscConfigPath"
Get-ChildItem $dscConfigPath | where {!$_.PSISContainer} | Remove-Item

$setupAccountName = $data.NonNodeData.SharePoint.ServiceAccounts.SetupAccount
$farmAccountName = $data.NonNodeData.SharePoint.ServiceAccounts.FarmAccount
$webAppAccountName = $data.NonNodeData.SharePoint.ServiceAccounts.WebAppPoolAccount
$svcAppAccountName = $data.NonNodeData.SharePoint.ServiceAccounts.ServicesAppPoolAccount
$srcContentAccessAccount = $data.NonNodeData.SharePoint.ServiceAccounts.ContentAccessAccount
#$ConnectAccounts = $data.NonNodeData.SharePoint.ServiceAccounts.ConnectionAccount

Write-Host "Getting Service Account Credentials" -ForegroundColor Green
$Domain = $data.NonNodeData.DomainDetails.DomainName
Do {
    $SetupAccount = Get-Credential -UserName $setupAccountName -Message "Setup Account"
}While ((Test-Credential -Credential $SetupAccount -Domain $Domain) -eq $false)
Do {
    $FarmAccount = Get-Credential  -UserName $farmAccountName -Message "Farm Account"
}While ((Test-Credential -Credential $FarmAccount -Domain $Domain) -eq $false)
Do {
    $WebAppPoolAccount = Get-Credential -UserName $webAppAccountName -Message "Web App Pool Account"
}While ((Test-Credential -Credential $WebAppPoolAccount -Domain $Domain) -eq $false)
Do {
    $ServicePoolAccount = Get-Credential -UserName $svcAppAccountName -Message "Svc App Pool Account"
}While ((Test-Credential -Credential $ServicePoolAccount -Domain $Domain) -eq $false)
Do {
    $ContentAccessAccount = Get-Credential -UserName $srcContentAccessAccount -Message "Search Default Content Access Account"
}While ((Test-Credential -Credential $ContentAccessAccount -Domain $Domain) -eq $false)
$passPhrase = Get-Credential -Message "Farm PassPhrase" -UserName "PassPhrase"
<#
if ($ConfigurationData.NonNodeData.SharePoint.Version -eq 2013)
{
    if(($ConnectAccounts).count -ge 1)
    {
        $ConnectAccount = @()
        $ConnectAccounts | ForEach-Object {
            $ConnectAccount += Get-Credential -UserName $_ -Message "UPA Sync Connection Account"
        }
    }
}
#>

Write-Host "Generating DSC Configuration into " $dscConfigPath -ForegroundColor Green

SharePointServer -FarmAccount $FarmAccount -WebPoolManagedAccount $WebAppPoolAccount -SPSetupAccount $SetupAccount -ServicePoolManagedAccount $ServicePoolAccount -ContentAccessAccount $ContentAccessAccount -outputpath $dscConfigPath -ConfigurationData $ConfigData -PassPhrase $passPhrase # -UPASyncConnectAccounts $ConnectAccount   

Write-Host "Creating checksums for all MOF..." -ForegroundColor Green
New-DSCCheckSum -Path $dscConfigPath -Force
<#
#Will need to find another value other than minrole
Write-Host "Removing old MOF from client servers" -ForegroundColor green
$data.AllNodes | ?{$_.MinRole} | ForEach-Object {
    $ServerCIMSession = New-CimSession -ComputerName $_.NodeName -Credential $SetupAccount
    Remove-DscConfigurationDocument -CimSession $ServerCIMSession -Stage Current,Pending,Previous -Force -Verbose
}
Get-CimSession | Remove-CimSession

Write-Host "Updating configuration on client machines" -ForegroundColor green
$data.AllNodes | ?{$_.MinRole} | ForEach-Object {
    $node = $_.NodeName
    Update-DscConfiguration -ComputerName $node -Verbose
}
#>