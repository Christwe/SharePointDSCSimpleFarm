#***************************************************************************************
# This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
# THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED 
# TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS for A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free right to use and modify 
# the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or 
# trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in 
# which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, 
# including attorneys fees, that arise or result from the use or distribution of the Sample Code.
#
# This script creates config and runs Set-DscLocalConfigurationManager on all nodes from $ConfigDataFile, as well if using Self signed cert it will deploy Root Chain to all nodes as well
#
# -Run this script as a local server Administrator
# -Run this script from elevaed prompt
# 
# Don't forget to: Set-ExecutionPolicy RemoteSigned
#
# Written by Chris Weaver (christwe@microsoft.com)
#
#****************************************************************************************

param (
    [string][Parameter(Mandatory=$true)] $ConfigDataFile = 'DSCConfigData.psd1',
    [string][Parameter(Mandatory=$true)] $ConfigFile = 'DSCConfig.ps1',
    [Parameter(Mandatory=$false)] $SetupAccount
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
$data = Invoke-Expression (Get-Content $ConfigData | out-string)

[DSCLocalConfigurationManager()]
configuration ClientConfigID
{
	param([string] $Server,[string]$url,[string]$path,[string]$RegistrationKey)

    Node $Server
    {
        Settings     
        {
            ConfigurationMode = ‘ApplyAndAutocorrect’
            RefreshMode = 'Pull'
            RefreshFrequencyMins = 30              # How often we look for new config on pull server
            RebootNodeIfNeeded = $true
            ActionAfterReboot = 'ContinueConfiguration'
            AllowModuleOverwrite = $true
            ConfigurationModeFrequencyMins = 15         #How often we check that server config is correct
        }
        ConfigurationRepositoryWeb PSDSCPullServer
        {
            ServerURL = $url
            RegistrationKey = $RegistrationKey
            ConfigurationNames = @($server)
            AllowUnsecureConnection = $true
        } 
        ReportServerWeb PSDSCPullServer          # https://msdn.microsoft.com/en-us/powershell/dsc/reportserver
        {
            ServerURL = $url
            RegistrationKey = $RegistrationKey
            AllowUnsecureConnection = $true
        }      
    }
}

$OutputDir = $Data.NonNodeData.DSCConfig.DSCConfigPath + "\Configurations\Client"
$DSCEndPointName = (($data.NonNodeData.DSCConfig.DSCConfigServiceEndPoint).split("/")[2]).split(":")[0]      # Pull the EndpointName out of url
$DSCEndPointSubjectName = "CN=" + (($data.NonNodeData.DSCConfig.DSCConfigServiceEndPoint).split("/")[2]).split(":")[0]
$pwd = ConvertTo-SecureString -String "P@ssword1" -Force -AsPlainText
Write-Host "DSCEndpointSubjectName $DSCEndPointSubjectName"
Write-Host "DSCEndPointName $DSCEndPointName"
Write-host "Will place Client MOF files in $OutputDir"

#Create OutputDir if it doesn't exist, if it does exist the cmdlet will continue without message
New-Item $OutputDir -ItemType directory -ErrorAction SilentlyContinue

Do {
    $SetupAccount = Get-Credential -UserName $data.NonNodeData.SharePoint.ServiceAccounts.SetupAccount -Message "Setup Account"
}While ((Test-Credential -Credential $SetupAccount -Domain $Domain) -eq $false)

$Pfx = $data.NonNodeData.DSCConfig.DSCConfigSharePath + "\Configurations\Cert\DSC.pfx"
$MachineDomain = $data.NonNodeData.DomainDetails.DomainName

$data.AllNodes | ?{$_.MinRole} | ForEach-Object {
    $node = $_.NodeName + "." + $MachineDomain

    if($data.NonNodeData.DSCConfig.DSCAcceptSelfSignedCertificates)
    {
        if(!(Test-WSMan -ComputerName $node -Authentication Credssp -Credential $SetupAccount -ea SilentlyContinue)) #Test remote connectivity and if it fails enable remote connectivity
        {
            Enable-WSManCredSSP -DelegateComputer $node -Role Client -Force
            Connect-WSMan $node
            Set-Item "WSMan:\$node\Service\Auth\CredSSP" -Value $True
            Invoke-Command -ComputerName $node -ScriptBlock {New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -ea SilentlyContinue} -Authentication Credssp -Credential $SetupAccount #Set IEESC for admins to Off
            Write-Host "Configured PS Remoting on server $node"
        }Else
        {
            Write-Host "Remoting already configured on server $node"
        }
        #Invoke-Command -ComputerName $node -ScriptBlock {Import-PfxCertificate -FilePath $args[0] -CertStoreLocation Cert:\LocalMachine\AuthRoot -Password $args[1]} -ArgumentList $Pfx,$Pwd -Authentication Credssp -Credential $SetupAccount

      #  $DSCCertThumbprint = (Get-ChildItem "Cert:\LocalMachine\My" | where {$_.Subject -eq $DSCEndPointSubjectName} | Select-object -First 1).Thumbprint

        If(Invoke-Command -ComputerName $node -ScriptBlock {Get-ChildItem -Path Cert:\LocalMachine\AuthRoot | where{$_.Subject -eq $Using:DSCEndPointSubjectName} | Test-Certificate -dnsname $Using:DSCEndPointName} -Authentication Credssp -Credential $SetupAccount)
        {
            write-host "Certificate is already in AuthRoot on server $node"
        }Else
        {
            Write-Host "Importing " $Pfx " to AuthRoot on server $node"
            Invoke-Command -ComputerName $node -ScriptBlock {Import-PfxCertificate -FilePath $Using:Pfx -CertStoreLocation Cert:\LocalMachine\AuthRoot -Password $Using:Pwd} -Authentication Credssp -Credential $SetupAccount
        }

        #If i need to create Wildcard cert for Webapp....
        #New-SelfSignedCertificate -Subject *.my.domain -DnsName my.domain, *.my.domain -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(10)
        
    }
    
    $ServerCIMSession = New-CimSession -ComputerName $_.NodeName -Credential $SetupAccount
    if((Get-DscLocalConfigurationManager -CimSession $ServerCIMSession -WarningAction SilentlyContinue).RefreshMode -eq "PUSH")
    {
        Write-host "Creating MOF File for Node: $node"
        ClientConfigID -server $_.Nodename -Url $Data.NonNodeData.DSCConfig.DSCConfigServiceEndPoint -Path $Data.NonNodeData.DSCConfig.DSCConfigModuleShare -RegistrationKey $Data.NonNodeData.DSCConfig.DSCConfigRegistryKey -OutputPath $OutputDir

        Write-Host "Pushing configuration to server: $node"
        Set-DscLocalConfigurationManager -ComputerName $_.NodeName -path $OutputDir -Verbose
    }Else
    {
        Write-Host "LCM on server $node is already configured"
    }
    $ServerCIMSession | Remove-CimSession
}