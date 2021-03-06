#***************************************************************************************
# This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.  
# THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED 
# TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS for A PARTICULAR PURPOSE.  We grant You a nonexclusive, royalty-free right to use and modify 
# the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or 
# trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in 
# which the Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, 
# including attorneys fees, that arise or result from the use or distribution of the Sample Code.
#
#
# -Run this script as a local server Administrator
# -Run this script from elevaed prompt
# 
# Don't forget to: Set-ExecutionPolicy RemoteSigned
#
# Written by Chris Weaver (christwe@microsoft.com) and Charles Teague (charlest@microsoft.com)
#
#****************************************************************************************

Configuration SharePointServer
{
    param (
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $FarmAccount,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $SPSetupAccount,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $WebPoolManagedAccount,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $ServicePoolManagedAccount,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $ContentAccessAccount,
        #[Parameter(Mandatory=$false)] $UPASyncConnectAccounts,
        [Parameter(Mandatory=$true)] [ValidateNotNullorEmpty()] [PSCredential] $PassPhrase
    )
    
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xPSDesiredStateConfiguration
    Import-DscResource -ModuleName SharePointDSC
    Import-DscResource -ModuleName xWebAdministration
    Import-DscResource -ModuleName xCredSSP
    Import-DSCResource -ModuleName xSystemSecurity
    Import-DSCResource -ModuleName CertificateDsc
    Import-DSCResource -ModuleName OfficeOnlineServerDSC
    Import-DSCResource -ModuleName NetworkingDSC
    Import-DSCResource -ModuleName xTimezone
    Import-DSCResource -ModuleName SQLServerDSC

    node $AllNodes.Where{$_.DisableIISLoopbackCheck}.NodeName
    {
        Registry DisableLoopBackCheck 
        {
            Ensure = "Present"
            Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
            ValueName = "DisableLoopbackCheck"
            ValueData = "1"
            ValueType = "Dword"
        }
    }

    <#
    node SSRS
    {
          xSPSSRSInstallIntegrated 

                 <#
        if ($node.SSRS) 
        {
            Package SSRSaddinInstall
            {
                PsDscRunAsCredential = $SPSetupAccount
                Path                 = $ConfigurationData.NonNodeData.SSRS.Installation.Binary
                ProductId            = "C3AF130F-8B2E-4D55-8AD1-F156F7C975E8"  
                Name                 = "Microsoft SQL Server 2014 RS Add-in for SharePoint"
                Ensure               = "Present"
                DependsOn            = $FarmInstallTask
            }
        }Else
        {
            Package SSRSaddinInstall
            {
                PsDscRunAsCredential = $SPSetupAccount
                Path                 = $ConfigurationData.NonNodeData.SSRS.Installation.Binary
                ProductId            = "C3AF130F-8B2E-4D55-8AD1-F156F7C975E8"
                Name                 = "Microsoft SQL Server 2014 RS Add-in for SharePoint"
                Ensure               = "Absent"
                DependsOn            = $FarmInstallTask
            }
        }
#>
    node $AllNodes.Where{$_.InstallPrereqs}.NodeName
    {                
        If ($ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallMode -eq $false)
        {
            if($ConfigurationData.NonNodeData.SharePoint.Version -eq 2016)
            {
                SPInstallPrereqs InstallPrereqs
            	{
                    IsSingleInstance = "Yes"
                	PsDscRunAsCredential = $SPSetupAccount
                	InstallerPath = (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.BinaryDir "\Prerequisiteinstaller.exe")
                	OnlineMode = $false
                	Ensure = "Present"
					
					SQLNCLI 			= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\sqlncli.msi")
					Sync 				= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\Synchronization.msi")
					AppFabric 			= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\WindowsServerAppFabricSetup_x64.exe")
					IDFX11 				= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\MicrosoftIdentityExtensions-64.msi")
					MSIPCClient 		= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\setup_msipc_x64.exe")
					KB3092423 			= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\AppFabric-KB3092423-x64-ENU.exe")
					WCFDataServices56 	= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\WcfDataServices56.exe")
					MSVCRT11			= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\vc_redist.x64.exe")
					MSVCRT14			= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\vcredist_x64.exe")
					ODBC				= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\msodbcsql.msi")
					DOTNETFX			= (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.PrereqInstallerPath "\NDP46-KB3045557-x86-x64-AllOS-ENU.exe")
				}
            }
        }else
		{
			SPInstallPrereqs InstallPrereqs
            {
                IsSingleInstance = "Yes"
                PsDscRunAsCredential = $SPSetupAccount
                InstallerPath = (Join-Path $ConfigurationData.NonNodeData.SharePoint.Installation.BinaryDir "\Prerequisiteinstaller.exe")
                OnlineMode = $true
                Ensure = "Present"
            }
		}
        $FarmPrereqInstallTask = "[SPInstallPrereqs]InstallPrereqs"
    }

    node $AllNodes.Where{$_.InstallSharePoint}.NodeName 
    {
        SPInstall InstallSP2016
        {
            IsSingleInstance = "Yes"
            PsDscRunAsCredential = $SPSetupAccount
            ProductKey           = $ConfigurationData.NonNodeData.SharePoint.installation.InstallKey
            BinaryDir            = $ConfigurationData.NonNodeData.SharePoint.installation.BinaryDir
            Ensure               = "Present"
            DependsOn            = $FarmPrereqInstallTask
        }
    }

    Node $AllNodes.Where{$_.FirstServer}.NodeName
    {
        #Need to make sure SharePoint is installed to all servers before creating farm
        $WaitNodes = ($AllNodes | Where-Object { $_.NodeName -ne $Node.NodeName -and $_.NodeName -ne '*'  }).NodeName #-and $_.NodeName -ne $FirstAppServer
        #$WaitNodes = ($AllNodes).NodeName
        WaitForAll InstallSharePointtoAllServers
        {
            ResourceName         = "[SPInstall]InstallSP2016"
            NodeName             = $WaitNodes
            RetryIntervalSec     = 30
            RetryCount           = 500
            PsDscRunAsCredential = $SPSetupAccount
        }

        If($AllNodes.Count -le 1)   #Not tested
        {
            $MinRole = "SingleServerFarm"
        }

        if($ConfigurationData.NonNodeData.DoDFarmStigs.v60009.Present)
        {
            $CentralAdminPort = $ConfigurationData.NonNodeData.DoDFarmStigs.v60009.PPSMAllowedPort   
        }Else
        {
            $CentralAdminPort = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdminPort
        }
        
        $FarmDatabaseServerString = $ConfigurationData.NonNodeData.SQLServer.FarmDatabaseServer + "\" + $ConfigurationData.NonNodeData.SQLServer.SQLInstance
        #Creates the Farm on the First Application Server
        SPFarm CreateSPFarm
        {
            IsSingleInstance = "Yes"
            Ensure = "Present"
            FarmConfigDatabaseName = $ConfigurationData.NonNodeData.SharePoint.Farm.ConfigurationDatabase
            DatabaseServer = $FarmDatabaseServerString
            FarmAccount = $FarmAccount
            Passphrase = $PassPhrase
            AdminContentDatabaseName = $ConfigurationData.NonNodeData.SharePoint.Farm.AdminContentDatabase
            RunCentralAdmin = $Node.CentralAdminHost
            CentralAdministrationUrl = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdminUrl
            CentralAdministrationPort = $CentralAdminPort
            CentralAdministrationAuth = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdminAuth
            ServerRole = $Node.MinRole
            DeveloperDashboard = $ConfigurationData.NonNodeData.SharePoint.Farm.DeveloperDashBoard 
            PsDscRunAsCredential     = $SPSetupAccount
            DependsOn                = "[WaitForAll]InstallSharePointtoAllServers"
        }
         
        #Add farm account to list so we don't remove from Farm group
        $FarmAdmins = @($ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.FarmAccount,$ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.SetupAccount)
        $FarmAdmins += $ConfigurationData.NonNodeData.SharePoint.Farm.FarmAdmins
        SPFarmAdministrators LocalFarmAdmins
        {
            IsSingleInstance = "Yes"
            Members              = $farmAdmins
            MembersToExclude     = $ConfigurationData.NonNodeData.SharePoint.Farm.ExcludeFromFarmAdmins
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        if($ConfigurationData.NonNodeData.FarmHardening.SetSPAntiVirus)
        {
            SPAntivirusSettings FarmAntivirusSettings
            {
                IsSingleInstance      = "Yes"
                ScanOnDownload        = $true
                ScanOnUpload          = $true
                AllowDownloadInfected = $false
                AttemptToClean        = $true
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn            = "[SPFarm]CreateSPFarm"
            }
        }

        SPPasswordChangeSettings ManagedAccountPasswordResetSettings  
        {  
            IsSingleInstance = "Yes"
            MailAddress                   = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.ManagedAccountPasswordResetSettings.AdministratorMailAddress
            DaysBeforeExpiry              = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.ManagedAccountPasswordResetSettings.SendmessageDaysBeforeExpiry
            PasswordChangeWaitTimeSeconds = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.ManagedAccountPasswordResetSettings.PasswordChangeTimeoutinSec
            NumberOfRetries               = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.ManagedAccountPasswordResetSettings.PasswordChangeNumberOfRetries
            PsDscRunAsCredential          = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPManagedAccount ServicePoolManagedAccount
        {
            AccountName          = $ServicePoolManagedAccount.UserName
            Account              = $ServicePoolManagedAccount
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPManagedAccount WebPoolManagedAccount
        {
            AccountName          = $WebPoolManagedAccount.UserName
            Account              = $WebPoolManagedAccount
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }  
        SPDiagnosticLoggingSettings ApplyDiagnosticLogSettings
        {
            IsSingleInstance = "Yes"
            LogPath                                     = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.Path
            LogSpaceInGB                                = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.MaxSizeGB
            AppAnalyticsAutomaticUploadEnabled          = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.AppAnalyticsAutomaticUploadEnabled
            CustomerExperienceImprovementProgramEnabled = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.CustomerExperienceImprovementProgramEnabled
            DaysToKeepLogs                              = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.DaysToKeep
            DownloadErrorReportingUpdatesEnabled        = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.DownloadErrorReportingUpdatesEnabled
            ErrorReportingAutomaticUploadEnabled        = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.ErrorReportingAutomaticUploadEnabled
            ErrorReportingEnabled                       = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.ErrorReportingEnabled
            EventLogFloodProtectionEnabled              = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.EventLogFloodProtectionEnabled
            EventLogFloodProtectionNotifyInterval       = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.EventLogFloodProtectionNotifyInterval 
            EventLogFloodProtectionQuietPeriod          = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.EventLogFloodProtectionQuietPeriod 
            EventLogFloodProtectionThreshold            = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.EventLogFloodProtectionThreshold 
            EventLogFloodProtectionTriggerPeriod        = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.EventLogFloodProtectionTriggerPeriod
            LogCutInterval                              = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.LogCutInterval 
            LogMaxDiskSpaceUsageEnabled                 = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.LogMaxDiskSpaceUsageEnabled
            ScriptErrorReportingDelay                   = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.ScriptErrorReportingDelay 
            ScriptErrorReportingEnabled                 = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.ScriptErrorReportingEnabled 
            ScriptErrorReportingRequireAuth             = $ConfigurationData.NonNodeData.SharePoint.DiagnosticLogs.ScriptErrorReportingRequireAuth  
            PsDscRunAsCredential                        = $SPSetupAccount
            DependsOn                                   = "[SPFarm]CreateSPFarm"
        }

        if($ConfigurationData.NonNodeData.FarmHardening.ULSLogBaseLevel.Present)
        {
            $ConfigurationData.NonNodeData.FarmHardening.ULSLogBaseLevel.Categories | ForEach-Object {
                $AreaName = $_.AreaName.Replace(" ","")
                $LogLevelResourceName = "SPLogLevel_$AreaName"
                SPLogLevel $LogLevelResourceName # https://github.com/PowerShell/SharePointDsc/wiki/SPLogLevel
                {
                    Name = "ULS_Log_Baseline_$AreaName"
                    SPLogLevelSetting = @(
                        MSFT_SPLogLevelItem {
                            Area           = $_.AreaName
                            Name           = $_.SubAreaName
                            TraceLevel     = $_.TraceLevel
                            EventLevel     = $_.EventLevel
                        }
                    )
                    PsDscRunAsCredential = $SetupAccount
                    DependsOn = "[SPDiagnosticLoggingSettings]ApplyDiagnosticLogSettings"
                }
            }
        }
        #Working
        <#
        If($ConfigurationData.NonNodeData.DoDFarmStigs.v59999)
        {
            SQLDatabaseRole IncludeFarmAdminPublic # dbcreator, and Securityadmin
            {
                ServerName           = $ConfigurationData.NonNodeData.SQLServer.ContentDatabaseServer
                InstanceName         = $ConfigurationData.NonNodeData.SQLServer.SQLInstance
                Database             = ""
                Name                 = "Public"
                Role                 = "Public"
                MembersToInclude     = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.FarmAccount
                Ensure               = "Present"
                PsDscRunAsCredential = $SPSetupAccount
            } 
        }
        #>
        if($ConfigurationData.NonNodeData.DoDFarmStigs.v59973.Present) 
        {
            SPIrmSettings EnableIRMSettings
            {
                IsSingleInstance = "Yes"
                Ensure = "Present"
                UseADRMS = $ConfigurationData.NonNodeData.DoDFarmStigs.v59973.RMSCertServer.RMSUseAD
                RMSServer = $ConfigurationData.NonNodeData.DoDFarmStigs.v59973.RMSCertServer
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[SPFarm]CreateSPFarm"
            }
        }Else
        {
            SPIrmSettings DisableIRMSettings
            {
                IsSingleInstance = "Yes"
                Ensure = "Absent"
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[SPFarm]CreateSPFarm"
            }
        }
        $ServiceDatabaseString = $ConfigurationData.NonNodeData.SQLServer.ServiceAppDatabaseServer + "\" + $ConfigurationData.NonNodeData.SQLServer.SQLInstance

        SPStateServiceApp StateServiceApp
        {
            Name                 = $ConfigurationData.NonNodeData.SharePoint.StateService.Name
            DatabaseName         = $ConfigurationData.NonNodeData.SharePoint.StateService.DatabaseName
            DatabaseServer       = $ServiceDatabaseString
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }
                
        foreach($Quota in $ConfigurationData.NonNodeData.SharePoint.Farm.SiteQuotaTemplates) {
            $QuotaInternalName = "QuotaTemplate_" + $Quota.QuotaName
            
            SPQuotaTemplate $QuotaInternalName
            {
                Ensure = "Present"
                Name = $Quota.QuotaName
                StorageMaxInMB = $Quota.QuotaStorageMaxInMB
                StorageWarningInMB = $Quota.QuotaStorageWarningInMB
                MaximumUsagePointsSolutions = $Quota.QuotaMaximumUsagePointsSolutions
                WarningUsagePointsSolutions = $Quota.QuotaWarningUsagePointsSolutions
                PsDscRunAsCredential          = $SPSetupAccount
                DependsOn            = "[SPFarm]CreateSPFarm"
            }
        }

        Script SetInboundMailSettings
        {
            GetScript = {
                Return @{Result = [string]$(Invoke-SPDscCommand -ScriptBlock {Get-SPServiceInstance | where {$_.TypeName -eq "Microsoft SharePoint Foundation Incoming E-Mail"} | Select-Object -First 1})}
            }
            SetScript = {
                $Enabled = $Using:ConfigurationData.NonNodeData.SharePoint.InboundEmail.Enable
                $EmailDomain = $Using:ConfigurationData.NonNodeData.SharePoint.InboundEmail.EmailDomain
                Invoke-SPDscCommand -ScriptBlock {
                    $svcinstance = Get-SPServiceInstance | where {($_.TypeName -eq "Microsoft SharePoint Foundation Incoming E-Mail") -and ($_.Status -eq "Online")}
                    $svcinstance.Service.Enabled = $args[0]
                    $svcinstance.Service.UseAutomaticSettings = $True 
                    $svcinstance.Service.ServerDisplayAddress = $args[1]
                    $svcinstance.Service.Update()
                } -Arguments $Enabled $EmailDomain
            }
            TestScript = {
                Invoke-SPDscCommand -ScriptBlock {
                    if(($svcinstance = Get-SPServiceInstance | where {($_.TypeName -eq "Microsoft SharePoint Foundation Incoming E-Mail") -and ($_.Status -eq "Online")}).Service.Enabled)
                    {
                        Return $true
                    }Else
                    {
                        Return $false
                    }
                }
            }
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn = "[SPFarm]CreateSPFarm"
        }

        SPServiceAppPool MainServiceAppPool
        {
            Name                 = $ConfigurationData.NonNodeData.SharePoint.Services.ApplicationPoolName
            ServiceAccount       = $ServicePoolManagedAccount.UserName
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPSecureStoreServiceApp SecureStoreServiceApp
        {
            Name                  = $ConfigurationData.NonNodeData.SharePoint.SecureStoreService.Name
            ApplicationPool       = $ConfigurationData.NonNodeData.SharePoint.Services.ApplicationPoolName
            AuditingEnabled       = $ConfigurationData.NonNodeData.SharePoint.SecureStoreService.AuditingEnabled
            AuditlogMaxSize       = $ConfigurationData.NonNodeData.SharePoint.SecureStoreService.AuditLogMaxSize
            DatabaseName          = $ConfigurationData.NonNodeData.SharePoint.SecureStoreService.DatabaseName
            DatabaseServer        = $ServiceDatabaseString
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = @("[SPServiceAppPool]MainServiceAppPool","[SPFarm]CreateSPFarm")
        }

        SPManagedMetaDataServiceApp ManagedMetadataServiceApp
        {  
            Name                 = $ConfigurationData.NonNodeData.SharePoint.ManagedMetadataService.Name
            ApplicationPool      = $ConfigurationData.NonNodeData.SharePoint.Services.ApplicationPoolName
            DatabaseName         = $ConfigurationData.NonNodeData.SharePoint.ManagedMetadataService.DatabaseName
            DatabaseServer       = $ServiceDatabaseString
            #TermStoreAdministrators = $ConfigurationData.NonNodeData.SharePoint.ManagedMetadataService.TermStoreAdministrators
            #ContentTypeHubUrl = ""
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn             = @("[SPServiceAppPool]MainServiceAppPool","[SPFarm]CreateSPFarm")
        }

        SPBCSServiceApp BCSServiceApp
        {
            Name                  = $ConfigurationData.NonNodeData.SharePoint.BCSService.Name
            ApplicationPool       = $ConfigurationData.NonNodeData.SharePoint.Services.ApplicationPoolName
            DatabaseName          = $ConfigurationData.NonNodeData.SharePoint.BCSService.DatabaseName
            DatabaseServer        = $ServiceDatabaseString
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = @("[SPServiceAppPool]MainServiceAppPool","[SPFarm]CreateSPFarm","[SPSecureStoreServiceApp]SecureStoreServiceApp")
        }

        SPAppManagementServiceApp AppManagementServiceApp
        {
            Name                  = $ConfigurationData.NonNodeData.SharePoint.AppManagementService.Name
            DatabaseName          = $ConfigurationData.NonNodeData.SharePoint.AppManagementService.DatabaseName
            DatabaseServer        = $ServiceDatabaseString
            ApplicationPool       = $ConfigurationData.NonNodeData.SharePoint.Services.ApplicationPoolName
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = @("[SPServiceAppPool]MainServiceAppPool","[SPFarm]CreateSPFarm")
        }

        SPSubscriptionSettingsServiceApp SubscriptionSettingsServiceApp
        {
            Name                  = $ConfigurationData.NonNodeData.SharePoint.SubscriptionSettingsService.Name
            DatabaseName          = $ConfigurationData.NonNodeData.SharePoint.SubscriptionSettingsService.DatabaseName
            DatabaseServer        = $ServiceDatabaseString
            ApplicationPool       = $ConfigurationData.NonNodeData.SharePoint.Services.ApplicationPoolName
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = @("[SPServiceAppPool]MainServiceAppPool","[SPFarm]CreateSPFarm")
        }

        SPVisioServiceApp VisioServiceApp
        {
            Name                  = $ConfigurationData.NonNodeData.SharePoint.VisioService.Name
            ApplicationPool       = $ConfigurationData.NonNodeData.SharePoint.Services.ApplicationPoolName
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = @("[SPServiceAppPool]MainServiceAppPool","[SPFarm]CreateSPFarm")
        }

        foreach($webApp in $ConfigurationData.NonNodeData.SharePoint.WebApplications) {
            $webAppInternalName = $webApp.Name.Replace(" ", "")

            If($ConfigurationData.NonNodeData.DoDFarmStigs.v59961)
            {
                $WebAppUseClassic = $false
                $WebAppDefaultZoneAuth = "Kerberos"
            }Else
            {
                $WebAppUseClassic = $webApp.UseClassic
                $WebAppDefaultZoneAuth = $WebApp.Auth_DefaultZone
            }

            If($ConfigurationData.NonNodeData.DoDFarmStigs.v59963.Present)
            {
                    Write-Verbose $webApp.url
                if($ConfigurationData.NonNodeData.DoDFarmStigs.v59963.WhitelistAnnonymousWebApp | where{$_ -match $webapp.Url})
                {
                    $WebAppAnonymousValue = $webApp.Anonymous
                    Write-Verbose "Set Anonymous User Value"
                }Else
                {
                     $WebAppAnonymousValue = $false                   
                     Write-Verbose "Set Anonymous False"
                }
            }Else
            {
                    $WebAppAnonymousValue = $webApp.Anonymous
                    Write-Verbose "Set Anonymous to user value"
            }

            #Create the Web Application
            if ($webApp.UseHostNamedSiteCollections -eq $true) 
            {
                $DatabaseServerString = $ConfigurationData.NonNodeData.SQLServer.ContentDatabaseServer + "\" + $ConfigurationData.NonNodeData.SQLServer.SQLInstance
                SPWebApplication $webAppInternalName
                {
                    Ensure                 = "Present"
                    UseClassic             = $WebAppUseClassic
                    Name                   = $webApp.Name
                    ApplicationPool        = $webApp.AppPool
                    ApplicationPoolAccount = $webApp.AppPoolAccount
                    AllowAnonymous         = $WebAppAnonymousValue
                    DatabaseName           = $webApp.DatabaseName
                    DatabaseServer         = $DatabaseServerString
                    WebAppUrl              = $webApp.Url
                    HostHeader             = ""   
                    Port                   = $WebApp.WebPort
                #Path = $WebApp.WebPath
                    PsDscRunAsCredential   = $SPSetupAccount
                    DependsOn              = "[SPManagedAccount]WebPoolManagedAccount"
                }
            }Else
            { 
                SPWebApplication $webAppInternalName
                {
                    Ensure                 = "Present"
                    UseClassic             = $WebAppUseClassic
                    Name                   = $webApp.Name
                    ApplicationPool        = $webApp.AppPool
                    ApplicationPoolAccount = $webApp.AppPoolAccount
                    AllowAnonymous         = $WebAppAnonymousValue
                    DatabaseName           = $webApp.DatabaseName
                    DatabaseServer         = $DatabaseServerString
                    WebAppUrl              = $webApp.Url
                    HostHeader             = $WebApp.BindingHostHeader   
                    Port                   = $WebApp.WebPort
                #Path = $WebApp.WebPath
                    PsDscRunAsCredential   = $SPSetupAccount
                    DependsOn              = "[SPManagedAccount]WebPoolManagedAccount"
                }
            }

            If($Node.DoDServerStigs.V59977)
            {
                $SecurityValidation = $true
                $SecurityValidationExpires = $true
                $SecurityValidationTimeOut = 15
            }
            Else
            {
                $SecurityValidation = $WebApp.SecurityValidation
                $SecurityValidationExpires = $WebApp.SecurityValidationExpires
                $SecurityValidationTimeOut = $WebApp.SecurityValidationTimeOutMinutes
            }

            If($Node.DoDServerStigs.V59957)
            {
                $BrowserFileHandling = "Strict"
            }Else
            {
                $BrowserFileHandling = $WebApp.BrowserFileHandling
            }

            $BLockedFileTypesWebAppInternalName = "BlockedFileTypes_ $webAppInternalName"
            If($ConfigurationData.NonNodeData.DoDFarmStigs.v59987.Present)
            {
                SPWebAppBlockedFileTypes $BLockedFileTypesWebAppInternalName
                {
                    WebAppUrl              = $WebApp.Url
                    Blocked          = $ConfigurationData.NonNodeData.DoDFarmStigs.v59987.BlockedFileList
                    PsDscRunAsCredential   = $SPSetupAccount
                    DependsOn = "[SPWebApplication]$webAppInternalName"
                }
            }Else
            {
                SPWebAppBlockedFileTypes $BLockedFileTypesWebAppInternalName
                {
                    WebAppUrl              = $WebApp.Url
                    Blocked          = $WebApp.BlockedFileTypes
                    PsDscRunAsCredential   = $SPSetupAccount
                    DependsOn = "[SPWebApplication]$webAppInternalName"
                }
                                
            }

            if($ConfigurationData.NonNodeData.DoDFarmStigs.v59991)
            {
                $WebAppOnlineWebGallery = $false
            }Else
            {
                $WebAppOnlineWebGallery = $WebApp.AllowOnlineWebPartCatalog
            }

            #Web Application Settings
            $webSettingsName = $webAppInternalName + "WebAppGeneralSettings"
            SPWebAppGeneralSettings $webSettingsName
            {
                WebAppUrl = $webApp.Url
                TimeZone = $WebApp.TimeZone 
                Alerts = $WebApp.Alerts
                AlertsLimit = $WebApp.AlertLimit
                RSS = $WebApp.RSS
                BlogAPI = $WebApp.BlogAPI
                BlogAPIAuthenticated = $WebApp.BlogAPIAuthenticated
                BrowserFileHandling = $BrowserFileHandling
                SecurityValidation = $SecurityValidation
                SecurityValidationExpires = $SecurityValidationExpires 
                SecurityValidationTimeOutMinutes = $SecurityValidationTimeOut
                RecycleBinEnabled = $WebApp.RecycleBinEnabled
                RecycleBinCleanupEnabled = $WebApp.RecycleBinCleanupEnabled
                RecycleBinRetentionPeriod = $WebApp.RecycleBinRetentionPeriod
                SecondStageRecycleBinQuota = $WebApp.SecondStageRecycleBinQuota
                MaximumUploadSize = $webApp.MaximumUploadSize
                CustomerExperienceProgram = $WebApp.CustomerExperienceProgram
                AllowOnlineWebPartCatalog = $WebAppOnlineWebGallery
                SelfServiceSiteCreationEnabled = $WebApp.SelfServiceSiteCreationEnabled
                PresenceEnabled = $WebApp.PresenceEnabled
                DefaultQuotaTemplate = $WebApp.DefaultQuotaTemplate
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[SPWebApplication]$webAppInternalName"
            }

            #Create the managed paths
            foreach($managedPath in $webApp.ManagedPaths) {
                SPManagedPath "$($webAppInternalName)Path$($managedPath.Path)" 
                {
                    WebAppUrl            = $webApp.Url
                    PsDscRunAsCredential = $SPSetupAccount
                    RelativeUrl          = $managedPath.Path
                    Explicit             = $managedPath.Explicit
                    HostHeader           = $false #$webApp.UseHostNamedSiteCollections
                    DependsOn            = "[SPWebApplication]$webAppInternalName"
                }
            }
            
            #Want to be able to setup Auth on multiple zones, but need to configure AAM first
            SPWebAppAuthentication "Authentication_$WebAppInternalName"
            {
                WebAppUrl   = $webApp.Url
                Default = @(
                    MSFT_SPWebAppAuthenticationMode {
                        AuthenticationMethod = $WebAppDefaultZoneAuth
                    }
                )
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn            = "[SPWebApplication]$webAppInternalName"
            }

            #Set the CachAccounts for the web application
            SPCacheAccounts "$($webAppInternalName)CacheAccounts"
            {
                WebAppUrl              = $webApp.Url
                SuperUserAlias         = $webApp.SuperUser
                SuperReaderAlias       = $webApp.SuperReader
                PsDscRunAsCredential   = $SPSetupAccount
                DependsOn              = "[SPWebApplication]$webAppInternalName"
            }

            #Ensure we have the Content Databases created foreach Site Collection
            #$scContentDatabases = ($webApp.Sitecollections).ContentDatabase | Sort-Object | Get-Unique
            #$scWaitTask = @("[SPWebApplication]$webAppInternalName")
                
            #Create the Site Collections
            foreach($siteCollection in $webApp.SiteCollections) {
                $internalSiteName = "SiteCollection_$WebAppInternalName$($siteCollection.Name.Replace(' ',''))"     #"$($webAppInternalName)Site$($siteCollection.Name.Replace(' ', ''))"
                if ($webApp.UseHostNamedSiteCollections -eq $true -and $siteCollection.HostNamedSiteCollection -eq $true) 
                {
                    if($siteCollection.Url.Count -eq 1) #Single URL being provisioned
                    {
                        SPSite $internalSiteName
                        {
                            Url                      = $siteCollection.Url
                            OwnerAlias               = $siteCollection.Owner
                            HostHeaderWebApplication = $webApp.Url
                            Name                     = $siteCollection.Name
                            Template                 = $siteCollection.Template
                            ContentDatabase          = $siteCollection.Database
                            CompatibilityLevel = $siteCollection.CompatibilityLevel
                            Description = $siteCollection.Description
                            Language = $siteCollection.Language
                            #OwnerEmail = $siteCollection.OwnerEmail
                            QuotaTemplate = $siteCollection.QuotaTemplate
                            #SecondaryEmail = $siteCollection.SecondaryEmail
                            #SecondaryOwnerAlias = $siteCollection.SecondaryOwnerAlias
                            CreateDefaultGroups = $siteCollection.CreateDefaultGroups
                            PsDscRunAsCredential     = $SPSetupAccount
                            DependsOn                = "[SPWebApplication]$webAppInternalName"
                        }
                    }Else   #Multiple URL being provisioned
                    {
                        $DefaultZoneUrl = $SiteCollection.Url[0]
                        Switch ($SiteCollection.Url.Count)
                        {
                            2 {$IntranetZoneUrl = $siteCollection.Url[1];$InternetZoneUrl = "";$ExtranetZoneUrl = "";$CustomZoneUrl = ""}
                            3 {$IntranetZoneUrl = $siteCollection.Url[1];$InternetZoneUrl = $siteCollection.Url[2];$ExtranetZoneUrl = "";$CustomZoneUrl = ""}
                            4 {$IntranetZoneUrl = $siteCollection.Url[1];$InternetZoneUrl = $siteCollection.Url[2];$ExtranetZoneUrl = $siteCollection.Url[3];$CustomZoneUrl = ""}
                            5 {$IntranetZoneUrl = $siteCollection.Url[1];$InternetZoneUrl = $siteCollection.Url[2];$ExtranetZoneUrl = $siteCollection.Url[3];$CustomZoneUrl = $siteCollection.Url[3]}
                        }

                        SPSite $internalSiteName
                        {
                            Url                      = $DefaultZoneUrl
                            OwnerAlias               = $siteCollection.Owner
                            HostHeaderWebApplication = $webApp.Url
                            Name                     = $siteCollection.Name
                            Template                 = $siteCollection.Template
                            ContentDatabase          = $siteCollection.Database
                            CompatibilityLevel = $siteCollection.CompatibilityLevel
                            Description = $siteCollection.Description
                            Language = $siteCollection.Language
                          #  OwnerEmail = $siteCollection.OwnerEmail
                            QuotaTemplate = $siteCollection.QuotaTemplate
                          #  SecondaryEmail = $siteCollection.SecondaryEmail
                            SecondaryOwnerAlias = $siteCollection.SecondaryOwnerAlias
                            CreateDefaultGroups = $siteCollection.CreateDefaultGroups
                            PsDscRunAsCredential     = $SPSetupAccount
                            DependsOn                = "[SPWebApplication]$webAppInternalName"
                        }

                        $internalURLS = $internalSiteName + "HNSCUrl"
                        SPSiteUrl $internalURLS
                        {
                            Url = $DefaultZoneUrl
                            Intranet = $IntranetZoneUrl
                            Internet = $InternetZoneUrl
                            Extranet = $ExtranetZoneUrl
                            Custom = $CustomZoneUrl
                            PsDscRunAsCredential     = $SPSetupAccount
                            DependsOn = "[SPSite]$internalSiteName"
                        } 
                                
                    }
                }Else 
                {
                    SPSite $internalSiteName
                    {
                        Url                      = $siteCollection.Url
                        OwnerAlias               = $siteCollection.Owner
                        Name                     = $siteCollection.Name
                        Template                 = $siteCollection.Template
                        ContentDatabase          = $siteCollection.Database
                        CompatibilityLevel = $siteCollection.CompatibilityLevel
                        Description = $siteCollection.Description
                        Language = $siteCollection.Language
                     #   OwnerEmail = $siteCollection.OwnerEmail
                        QuotaTemplate = $siteCollection.QuotaTemplate
                       # SecondaryEmail = $siteCollection.SecondaryEmail
                     #   SecondaryOwnerAlias = $siteCollection.SecondaryOwnerAlias
                        CreateDefaultGroups = $siteCollection.CreateDefaultGroups
                        PsDscRunAsCredential     = $SPSetupAccount
                        DependsOn                = "[SPWebApplication]$webAppInternalName"
                    }
                }
            }

            #Enforce auditing on all Site Collections in Web App
            if($ConfigurationData.NonNodeData.DoDFarmStigs.v59941.Present)
            {
                $AuditMask = $ConfigurationData.NonNodeData.DoDFarmStigs.v59941.AuditElements
                $WebAppUrl = $webapp.url
                $DaystoTrim = $ConfigurationData.NonNodeData.DoDFarmStigs.v59941.DaystoTrim

                $EnforceAuditing = "EnforceAuditingonAllSiteCollections_$webAppInternalName"
                Script $EnforceAuditing
                {                             
                    GetScript = {
                        #Return @{Result = [string]$(Invoke-SPDscCommand -Credential $SPSetupAccount -ScriptBlock {(Get-SPWebApplication $args[0]).Sites | where {$_.Audit.AuditFlags -eq $args[1]} | Select-Object -First 1} -Arguments $Using:WebApp.url,"All")}
                        Return @{Result = [string]$("Hello World")}
                    }
                    TestScript = {
                        Return $false
                    }
                    SetScript = {
                       # $SPDscCommandParam = @($WebAppUrl,$AuditMask,$DaystoTrim)
                        Invoke-SPDscCommand -Credential $FarmAccount -ScriptBlock {
                            $AuditFlag = $args[1]
                            $Url = $args[0]
                            $Retention = $args[2]
                            Write-Verbose -Message ("Web Application Url is: {0}" -f $Url)
                            Write-Verbose -Message ("Auditflag value is: {0}" -f $AuditFlag) 
                            Write-Verbose -Message ("Audit trimming is: {0}" -f $Retention)
                            Get-SPSite -WebApplication $Url -Limit All | ForEach-Object {
                                Write-Verbose -Message ("Setting audit on: {0}" -f $_.url)
                                $_.TrimAuditLog = $true
                                $_.AuditLogTrimmingRetention = $Retention
                                $_.Audit.AuditFlags = $AuditFlag
                                $_.Audit.Update()
                            }
                        } -Arguments @($using:WebAppUrl, $Using:AuditMask, $Using:DaystoTrim)
                    }

                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn = "[SPFarm]CreateSPFarm"
                }
            }

            #Enforce creation of Site Column with required 
            if($ConfigurationData.NonNodeData.DoDFarmStigs.v59935)
            {
                $EnforceSecurityColumnCreation = "$EnforceSecurityColumnCreationonAllSiteCollections_$webAppInternalName"
                Script $EnforceSecurityColumnCreation
                {                             
                    GetScript = {
                        Return @{Result = [string]$("Hello World")}
                    }
                    TestScript = {
                        Return $false
                    }
                    SetScript = {
                        Invoke-SPDscCommand -Credential $FarmAccount -ScriptBlock {
                            (Get-SPSite -WebApplication $Url -Limit All | Get-SPWeb -Limit All).Lists | ForEach-Object {
                                
                            }
                        } -Arguments @()
                    }
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn = "[SPFarm]CreateSPFarm"
                }
            }
        }
        foreach($EmailSetting in $ConfigurationData.NonNodeData.SharePoint.OutgoingEmail) {
            $Name = $EmailSetting.WebAppUrl
            SPOutgoingEmailSettings $Name
            {
                WebAppUrl            = $EmailSetting.WebAppUrl
                SMTPServer           = $EmailSetting.SMTPServer
                FromAddress          = $EmailSetting.FromAddress
                ReplyToAddress       = $EmailSetting.ReplyToAddress
                CharacterSet         = $EmailSetting.CharacterSet
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn            = "[SPWebApplication]$webAppInternalName"
            }
        }

        if($ConfigurationData.NonNodeData.DoDFarmStigs.v59949.Present)
        {
          
            $Name = "CopyFile_" + $ConfigurationData.NonNodeData.DoDFarmStigs.v59949.SolutionName
            $SourcePath = $ConfigurationData.NonNodeData.DoDFarmStigs.v59949.SolutionPath + "\" + $ConfigurationData.NonNodeData.DoDFarmStigs.v59949.SolutionName
            $DestinationPath = $ConfigurationData.NonNodeData.DSCConfig.DSCLocalFolder + "\" + $ConfigurationData.NonNodeData.DoDFarmStigs.v59949.SolutionName

            File $Name
            {
                Ensure = "Present"
                Type = "File"
                Recurse = $false
                SourcePath = $SourcePath 
                DestinationPath = $DestinationPath
                Force = $true
                MatchSource = $true
                Credential = $SPSetupAccount
              #  DependsOn = "[File]LocalScratchFolder"
            }

            SPFarmSolution DeployTermsofUseSolution
            {
                Ensure = "Present"
                #WebAppUrls = ""
                Name = $ConfigurationData.NonNodeData.DoDFarmStigs.v59949.SolutionName
                LiteralPath = $DestinationPath
                Version = $ConfigurationData.NonNodeData.DoDFarmStigs.v59949.VersionNumber
                Deployed = $true
                SolutionLevel = "All"
                PsDscRunAsCredential     = $SPSetupAccount
                DependsOn                = @("[SPWebApplication]$webAppInternalName", "[File]$Name")
            }
        }

        SPUserProfileServiceApp UserProfileServiceApp
        {
            Ensure               = "Present"
            NoILMUsed            = $ConfigurationData.NonNodeData.SharePoint.UserProfileService.UseADImport
            ProxyName            = $ConfigurationData.NonNodeData.SharePoint.UserProfileService.ProxyName
            Name                 = $ConfigurationData.NonNodeData.SharePoint.UserProfileService.Name
            ApplicationPool      = $ConfigurationData.NonNodeData.SharePoint.Services.ApplicationPoolName
            MySiteHostLocation   = $ConfigurationData.NonNodeData.SharePoint.UserProfileService.MySiteUrl
            ProfileDBName        = $ConfigurationData.NonNodeData.SharePoint.UserProfileService.ProfileDB
            ProfileDBServer      = $ServiceDatabaseString
            SocialDBName         = $ConfigurationData.NonNodeData.SharePoint.UserProfileService.SocialDB
            SocialDBServer       = $ServiceDatabaseString
            SyncDBName           = $ConfigurationData.NonNodeData.SharePoint.UserProfileService.SyncDB
            SyncDBServer         = $ServiceDatabaseString
            EnableNetbios        = $ConfigurationData.NonNodeData.SharePoint.UserProfileService.NetbiosEnable
            # FarmAccount          = $FarmAccount
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = @('[SPServiceAppPool]MainServiceAppPool', '[SPManagedMetaDataServiceApp]ManagedMetadataServiceApp', '[SPManagedAccount]WebPoolManagedAccount')
        }

        SPSearchServiceApp SearchServiceApp
        {  
            Ensure                = "Present"
            Name                  = $ConfigurationData.NonNodeData.SharePoint.Search.Name
            DatabaseName          = $ConfigurationData.NonNodeData.SharePoint.Search.DatabaseName
            DatabaseServer        = $ServiceDatabaseString
            ApplicationPool       = $ConfigurationData.NonNodeData.SharePoint.Services.ApplicationPoolName
            DefaultContentAccessAccount = $ContentAccessAccount
            CloudIndex            = $ConfigurationData.NonNodeData.SharePoint.Search.CloudSSA
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn            = @('[SPServiceAppPool]MainServiceAppPool', '[SPManagedMetaDataServiceApp]ManagedMetadataServiceApp', '[SPManagedAccount]WebPoolManagedAccount')
        }

        ForEach($SSA in $ConfigurationData.NonNodeData.SharePoint.Search)
        {
            $SSAName = $SSA.Name
            SPSearchTopology $SSAName
            {
                ServiceAppName          = $SSA.Name
                Admin                   = $SSA.SearchTopology.Admin
                Crawler                 = $SSA.SearchTopology.Crawler
                ContentProcessing       = $SSA.SearchTopology.ContentProcesing
                AnalyticsProcessing     = $SSA.SearchTopology.AnalyticsProcesing
                QueryProcessing         = $SSA.SearchTopology.QueryProcesing
                FirstPartitionDirectory = $SSA.SearchTopology.IndexPartition0Folder
                IndexPartition          = $SSA.SearchTopology.IndexPartition0
                PsDscRunAsCredential    = $SPSetupAccount
                DependsOn               = "[SPSearchServiceApp]SearchServiceApp"
            }
            ForEach($Partition in $ConfigurationData.NonNodeData.SharePoint.Search.SearchTopology.IndexPartitions)
            { 
                $IndexName = $SSA.Name + "Partition" + $Partition.Index
                SPSearchIndexPartition $IndexName
                {
                    Servers              = $Partition.Servers
                    Index                = $Partition.Index
                    RootDirectory        = $Partition.IndexPartitionFolder
                    ServiceAppName       = $SSA.Name
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = "[SPSearchTopology]$SSAName"
                }
            }
        }

        #Needs to be tested
        $OOSMasterServerName = $AllNodes.Where{$_.OOSMasterServer}.NodeName

        if($OOSMasterServerName)
        {
            $ConfigurationData.NonNodeData.OfficeOnline.Binding | ForEach-Object {
                $ZoneName = "OOSServerBinding_" + $ConfigurationData.NonNodeData.OfficeOnline.Binding.Zone
                if($_.ServerName)
                {
                    SPOfficeOnlineServerBinding $ZoneName 
                    {
                        Ensure               = "Present"
                        Zone                 = $_.Zone
                        DnsName              = $_.ServerName
                        PsDscRunAsCredential = $SetupAccount
                    }
                }Else
                {
                    SPOfficeOnlineServerBinding $ZoneName 
                    {
                        Ensure               = "Present"
                        Zone                 = $_.Zone
                        DnsName              = $OOSMasterServerName
                        PsDscRunAsCredential = $SetupAccount
                    }
                }
            }
        }
    }

    Node $AllNodes.Where{$_.FirstServer -eq $false}.NodeName
    {
        #Wait for FirstServer to create farm
        WaitForAll WaitForFarmToExist
        {
            ResourceName         = "[SPFarm]CreateSPFarm"
            NodeName             = $AllNodes.Where{$_.FirstServer}.NodeName
            RetryIntervalSec     = 30
            RetryCount           = 500
            PsDscRunAsCredential = $SPSetupAccount
        } 

        if($ConfigurationData.NonNodeData.DoDFarmStigs.v60009.Present)
        {
            $CentralAdminPort = $ConfigurationData.NonNodeData.DoDFarmStigs.v60009.PPSMAllowedPort   
        }Else
        {
            $CentralAdminPort = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdminPort
        }
        
        $FarmDatabaseServerString = $ConfigurationData.NonNodeData.SQLServer.FarmDatabaseServer + "\" + $ConfigurationData.NonNodeData.SQLServer.SQLInstance
        #Joins the server to the Farm
        SPFarm JoinSPFarm
        {
            IsSingleInstance = "Yes"
            Ensure = "Present"
            FarmConfigDatabaseName = $ConfigurationData.NonNodeData.SharePoint.Farm.ConfigurationDatabase
            DatabaseServer = $FarmDatabaseServerString
            FarmAccount = $FarmAccount
            Passphrase = $PassPhrase
            AdminContentDatabaseName = $ConfigurationData.NonNodeData.SharePoint.Farm.AdminContentDatabase
            RunCentralAdmin = $Node.CentralAdminHost
            CentralAdministrationUrl = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdminUrl
            CentralAdministrationPort = $CentralAdminPort
            CentralAdministrationAuth = $ConfigurationData.NonNodeData.SharePoint.Farm.CentralAdminAuth
            ServerRole = $Node.MinRole
            DeveloperDashboard = $ConfigurationData.NonNodeData.SharePoint.Farm.DeveloperDashBoard 
            PsDscRunAsCredential     = $SPSetupAccount
            DependsOn                = "[WaitForAll]WaitForFarmToExist"
        }
    }

    <#
    Node $AllNodes.where{$_.CentralAdminHost}.NodeName
    {
        #Set bindings
    }

    Node $AllNodes.Where{$_.MinRole -eq "WebFrontEnd" -or $_.MinRole -eq "SingleServerFarm" -or $_.MinRole -eq "WebFrontEndWithDistributedCache" -or ($_.MinRole -eq "Custom" -and $_.CustomServices.WebFrontEnd)}.NodeName
    {
        foreach($webApp in $ConfigurationData.NonNodeData.SharePoint.WebApplications) {
            $webAppInternalName = $webApp.Name.Replace(" ", "")
            
            If($ConfigurationData.NonNodeData.DoDFarmStigs.v59961)
            {
            }Else
            {
            }
            WaitForAll $webAppInternalName
            {
                ResourceName         = "[SPWebApplication]$webAppInternalName"
                NodeName             = $AllNodes.Where{$_.FirstServer}.NodeName
                RetryIntervalSec     = 30
                RetryCount           = 500
                PsDscRunAsCredential = $SPSetupAccount
            }

            if($WebApp.WebPort -eq 443)
            {
                #Need to import cert to server
                $CertificateInternalName = "CertificateImport_$WebAppInternalName"

                $secpasswd = ConvertTo-SecureString $webApp.PFXPassword -AsPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential ("username", $secpasswd)

                PfxImport $CertificateInternalName
                {
                    Ensure = "Present"
                    Thumbprint = $WebApp.SSLCertificateThumbPrint
                    Path       = $WebApp.SSLCertificate
                    Location   = 'LocalMachine'
                    Store      = 'My'
                    Exportable = $true
                    Credential = $Credential
                    PsDscRunAsCredential = $SPSetupAccount
                }

                $CertificateRootName = "RootCertificateImport_$WebAppInternalName"
                PfxImport $CertificateRootName
                {
                    Ensure = "Present"
                    Thumbprint = $WebApp.SSLCertificateThumbPrint
                    Path       = $WebApp.SSLCertificate
                    Location   = 'LocalMachine'
                    Store      = 'Root'
                    Exportable = $true
                    Credential = $Credential
                    PsDscRunAsCredential = $SPSetupAccount
                }
                
                if ($webApp.UseHostNamedSiteCollections -eq $true) 
                {          
                    xWebSite "$WebAppInternalName"         
                    {
                        Ensure = "Present"
                        Name = $WebApp.Name
                        State = "Started"

                        BindingInfo = MSFT_xWebBindingInformation
                        {
                            Protocol = "HTTPS"
                            IPAddress = "*"
                            Port     = $WebApp.WebPort
                            CertificateThumbprint = $WebApp.SSLCertificateThumbPrint
                            HostName = "" 
                        }
                        DependsOn = @("[WaitForAll]$webAppInternalName","[PfxImport]$CertificateInternalName")
                                        PsDscRunAsCredential = $SPSetupAccount
                    }
                }Else
                {
                    xWebSite "$WebAppInternalName"         
                    {
                        Ensure = "Present"
                        Name = $WebApp.Name
                        State = "Started"

                        BindingInfo = MSFT_xWebBindingInformation
                        {
                            Protocol = "HTTPS"
                            IPAddress = "*"
                            Port     = $WebApp.WebPort   
                            CertificateThumbprint = $WebApp.SSLCertificateThumbPrint
                            HostName = $WebApp.BindingHostHeader 
                        }
                        DependsOn = @("[WaitForAll]$webAppInternalName","[PfxImport]$CertificateInternalName")
                                        PsDscRunAsCredential = $SPSetupAccount
                    }
                }
            }Else
            {
                if ($webApp.UseHostNamedSiteCollections -eq $true) 
                {          
                    xWebSite "$WebAppInternalName"         
                    {
                        Ensure = "Present"
                        Name = $WebApp.Name
                        State = "Started"

                        BindingInfo = MSFT_xWebBindingInformation
                        {
                            Protocol = "HTTP"
                            IPAddress = "*"
                            Port     = $WebApp.WebPort
                            HostName = "" 
                        }
                        DependsOn = "[WaitForAll]$webAppInternalName"
                                        PsDscRunAsCredential = $SPSetupAccount
                    }
                }Else
                {
                    xWebSite "$WebAppInternalName"         
                    {
                        Ensure = "Present"
                        Name = $WebApp.Name
                        State = "Started"

                        BindingInfo = MSFT_xWebBindingInformation
                        {
                            Protocol = "HTTP"
                            IPAddress = "*"
                            Port     = $WebApp.WebPort   
                            HostName = $WebApp.BindingHostHeader 
                        }
                        DependsOn = "[WaitForAll]$webAppInternalName"
                                        PsDscRunAsCredential = $SPSetupAccount
                    }
                }
            }
        }
    }
    #>
    
    Node $AllNodes.Where{$_.Role -eq "OOS"}.NodeName
    {
        $FirewallName = ($ConfigurationData.NonNodeData.OfficeOnline.Firewall.DisplayName).Replace("","")
        Firewall OfficeOnlineServerInboundRule
        {
            Name = $FirewallName
            DisplayName = $ConfigurationData.NonNodeData.OfficeOnline.Firewall.DisplayName
            Group = $ConfigurationData.NonNodeData.OfficeOnline.Firewall.CustomGroup
            Ensure = "Present"
            Enabled = $ConfigurationData.NonNodeData.OfficeOnline.Firewall.Enabled
            Action = "Allow"
            Profile = $ConfigurationData.NonNodeData.OfficeOnline.Firewall.Profile
            Direction = $ConfigurationData.NonNodeData.OfficeOnline.Firewall.Direction
            LocalPort = $ConfigurationData.NonNodeData.OfficeOnline.Firewall.LocalPort
            Protocol = $ConfigurationData.NonNodeData.OfficeOnline.Firewall.Protocol
            Description = "Firewall rule to enable communication between OOS servers managed via DSC"

        }

        WindowsFeatureSet OfficeOnlineServerFeatures 
        { 
            Ensure = "Present"
            Name   = @('Web-Server','Web-Mgmt-Tools','Web-Mgmt-Console','Web-WebServer','Web-Common-Http','Web-Default-Doc','Web-Static-Content','Web-Performance','Web-Stat-Compression','Web-Dyn-Compression','Web-Security','Web-Filtering','Web-Windows-Auth','Web-App-Dev','Web-Net-Ext45','Web-Asp-Net45','Web-ISAPI-Ext','Web-ISAPI-Filter','Web-Includes','InkandHandwritingServices','NET-Framework-Features','NET-Framework-Core','NET-HTTP-Activation','NET-Non-HTTP-Activ','NET-WCF-HTTP-Activation45','Windows-Identity-Foundation')
            PsDscRunAsCredential = $SPSetupAccount             
        }

        if((($ConfigurationData.NonNodeData.OfficeOnline.Installation.BinaryDir).EndsWith("Setup.exe")) -or (($ConfigurationData.NonNodeData.OfficeOnline.Installation.BinaryDir).EndsWith("setup.exe")))
        {
            $BinaryDir = $ConfigurationData.NonNodeData.OfficeOnline.Installation.BinaryDir
        }Else
        {
            $BinaryDir = $ConfigurationData.NonNodeData.OfficeOnline.Installation.BinaryDir + "\Setup.exe"
        }
        
        OfficeOnlineServerInstall InstallOfficeOnlineServerBinaries 
        {
            Ensure = "Present"
            Path = $BinaryDir
            DependsOn = @("[WindowsFeatureSet]OfficeOnlineServerFeatures","[Firewall]OfficeOnlineServerInboundRule")
        }
        
        if($Node.MasterServer)
        {
            File OfficeInlineServerCacheFolder 
            {
                Type = "Directory"
                DestinationPath = $ConfigurationData.NonNodeData.OfficeOnline.CacheLocation
                PsDscRunAsCredential = $SPSetupAccount
                Ensure = "Present"
            }

            File OfficeInlineServerLogLocation 
            {
                Type = "Directory"
                DestinationPath = $ConfigurationData.NonNodeData.OfficeOnline.LogLocation
                PsDscRunAsCredential = $SPSetupAccount
                Ensure = "Present"
            }

            File OfficeInlineServerRenderingLocalCacheLocation 
            {
                Type = "Directory"
                DestinationPath = $ConfigurationData.NonNodeData.OfficeOnline.RenderingLocalCacheLocation
                PsDscRunAsCredential = $SPSetupAccount
                Ensure = "Present"
            }

            OfficeOnlineServerFarm OfficeOnlineServerFarmMachine
            {
                AllowCEIP = $ConfigurationData.NonNodeData.OfficeOnline.AllowCEIP
                AllowHTTP = $ConfigurationData.NonNodeData.OfficeOnline.AllowHTTP
                CacheLocation = $ConfigurationData.NonNodeData.OfficeOnline.CacheLocation
                CacheSizeinGB = $ConfigurationData.NonNodeData.OfficeOnline.CacheSizeinGB
                CertificateName = $ConfigurationData.NonNodeData.OfficeOnline.CertificateName
                ClipartEnabled = $ConfigurationData.NonNodeData.OfficeOnline.ClipartEnabled
                DocumentInfoCacheSize = $ConfigurationData.NonNodeData.OfficeOnline.DocumentInfoCacheSize
                EditingEnabled = $ConfigurationData.NonNodeData.OfficeOnline.EditingEnabled
                ExcelAllowExternalData = $ConfigurationData.NonNodeData.OfficeOnline.ExcelAllowExternalData
                ExcelConnectionLifetime = $ConfigurationData.NonNodeData.OfficeOnline.ExcelConnectionLifetime
                ExcelExternalDataCacheLifetime = $ConfigurationData.NonNodeData.OfficeOnline.ExcelExternalDataCacheLifetime
                ExcelPrivateBytesMax = $ConfigurationData.NonNodeData.OfficeOnline.ExcelPrivateBytesMax
                ExcelRequestDurationMax = $ConfigurationData.NonNodeData.OfficeOnline.ExcelRequestDurationMax
                ExcelSessionTimeout = $ConfigurationData.NonNodeData.OfficeOnline.ExcelSessionTimeout
                ExcelUdfsAllowed = $ConfigurationData.NonNodeData.OfficeOnline.ExcelUdfsAllowed
                ExcelWarnOnDataRefresh = $ConfigurationData.NonNodeData.OfficeOnline.ExcelWarnOnDataRefresh
                ExcelWorkbookSizeMax = $ConfigurationData.NonNodeData.OfficeOnline.ExcelWorkbookSizeMax
                ExcelMemoryCacheThreshold = $ConfigurationData.NonNodeData.OfficeOnline.ExcelMemoryCacheThreshold
                ExcelUnusedObjectAgeMax = $ConfigurationData.NonNodeData.OfficeOnline.ExcelUnusedObjectAgeMax
                ExcelCachingUnusedFiles = $ConfigurationData.NonNodeData.OfficeOnline.ExcelCachingUnusedFiles
                ExcelAbortOnRefreshOnOpenFail = $ConfigurationData.NonNodeData.OfficeOnline.ExcelAbortOnRefreshOnOpenFail
                ExcelAutomaticVolatileFunctionCacheLifetime = $ConfigurationData.NonNodeData.OfficeOnline.ExcelAutomaticVolatileFunctionCacheLifetime
                ExcelConcurrentDataRequestsPerSessionMax = $ConfigurationData.NonNodeData.OfficeOnline.ExcelConcurrentDataRequestsPerSessionMax
                ExcelDefaultWorkbookCalcMode = $ConfigurationData.NonNodeData.OfficeOnline.ExcelDefaultWorkbookCalcMode
                ExcelRestExternalDataEnabled = $ConfigurationData.NonNodeData.OfficeOnline.ExcelRestExternalDataEnabled
                ExcelChartAndImageSizeMax = $ConfigurationData.NonNodeData.OfficeOnline.ExcelChartAndImageSizeMax
                ExternalURL = $ConfigurationData.NonNodeData.OfficeOnline.ExternalURL
                FarmOU = $ConfigurationData.NonNodeData.OfficeOnline.FarmOU
                InternalURL = $ConfigurationData.NonNodeData.OfficeOnline.InternalURL
                LogLocation = $ConfigurationData.NonNodeData.OfficeOnline.LogLocation
                LogRetentionInDays = $ConfigurationData.NonNodeData.OfficeOnline.LogRetentionInDays
                LogVerbosity = $ConfigurationData.NonNodeData.OfficeOnline.LogVerbosity
                MaxMemoryCacheSizeInMB = $ConfigurationData.NonNodeData.OfficeOnline.MaxMemoryCacheSizeInMB
                MaxTranslationCharacterCount = $ConfigurationData.NonNodeData.OfficeOnline.MaxTranslationCharacterCount
                OpenFromUncEnabled = $ConfigurationData.NonNodeData.OfficeOnline.OpenFromUncEnabled
                OpenFromUrlEnabled = $ConfigurationData.NonNodeData.OfficeOnline.OpenFromUrlEnabled
                OpenFromUrlThrottlingEnabled = $ConfigurationData.NonNodeData.OfficeOnline.OpenFromUrlThrottlingEnabled
                Proxy = $ConfigurationData.NonNodeData.OfficeOnline.Proxy
                RecycleActiveProcessCount = $ConfigurationData.NonNodeData.OfficeOnline.RecycleActiveProcessCount
                RenderingLocalCacheLocation = $ConfigurationData.NonNodeData.OfficeOnline.RenderingLocalCacheLocation
                SSLOffloaded = $ConfigurationData.NonNodeData.OfficeOnline.SSLOffloaded
                TranslationEnabled = $ConfigurationData.NonNodeData.OfficeOnline.TranslationEnabled
                TranslationServiceAddress = $ConfigurationData.NonNodeData.OfficeOnline.TranslationServiceAddress
                TranslationServiceAppId = $ConfigurationData.NonNodeData.OfficeOnline.TranslationServiceAppId
                AllowOutboundHttp = $ConfigurationData.NonNodeData.OfficeOnline.AllowOutboundHttp
                ExcelUseEffectiveUserName = $ConfigurationData.NonNodeData.OfficeOnline.ExcelUseEffectiveUserName
                S2SCertificateName = $ConfigurationData.NonNodeData.OfficeOnline.S2SCertificateName
                RemovePersonalInformationFromLogs = $ConfigurationData.NonNodeData.OfficeOnline.RemovePersonalInformationFromLogs
                PicturePasteDisabled = $ConfigurationData.NonNodeData.OfficeOnline.PicturePasteDisabled
                DependsOn = @("[OfficeOnlineServerInstall]InstallOfficeOnlineServerBinaries","[File]OfficeInlineServerCacheFolder","[File]OfficeInlineServerLogLocation","[File]OfficeInlineServerRenderingLocalCacheLocation")
            }
        }Else
        {
            File OfficeInlineServerCacheFolder 
            {
                Type = "Directory"
                DestinationPath = $ConfigurationData.NonNodeData.OfficeOnline.CacheLocation
                PsDscRunAsCredential = $SPSetupAccount
                Ensure = "Present"
            }

            File OfficeInlineServerLogLocation 
            {
                Type = "Directory"
                DestinationPath = $ConfigurationData.NonNodeData.OfficeOnline.LogLocation
                PsDscRunAsCredential = $SPSetupAccount
                Ensure = "Present"
            }

            File OfficeInlineServerRenderingLocalCacheLocation 
            {
                Type = "Directory"
                DestinationPath = $ConfigurationData.NonNodeData.OfficeOnline.RenderingLocalCacheLocation
                PsDscRunAsCredential = $SPSetupAccount
                Ensure = "Present"
            }

            $FarmMasterName = $AllNodes.Where{$_.OOSMasterServer}.NodeName
            OfficeOnlineServerMachine WebAppMachine
            {
                Ensure = "Present"
                MachineToJoin = $FarmMasterName
                Roles = $node.OOSRole
                DependsOn = @("[OfficeOnlineServerInstall]InstallOfficeOnlineServerBinaries","[File]OfficeInlineServerCacheFolder","[File]OfficeInlineServerLogLocation","[File]OfficeInlineServerRenderingLocalCacheLocation")
            }
        }
    }

    Node $AllNodes.NodeName
    {
        xCredSSP CredSSPServer { Ensure = "Present"; Role = "Server" } 
        xCredSSP CredSSPClient { Ensure = "Present"; Role = "Client"; DelegateComputers = "*.$($ConfigurationData.NonNodeData.DomainDetails.DomainName)"}

        if ($ConfigurationData.NonNodeData.DisableIEESC.Admin)
        {
            Registry DisableIEESCAdmin
            {
                Ensure = "Present"
                Key = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"# "HKLM:\System\CurrentControlSet\Control\Lsa"
                ValueName = "IsInstalled"
                ValueData = "0"
                ValueType = "Dword"
                PsDscRunAsCredential = $SPSetupAccount
            }
        }Else
        {
            Registry EnableIEESCAdmin
            {
                Ensure = "Present"
                Key = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"# "HKLM:\System\CurrentControlSet\Control\Lsa"
                ValueName = "IsInstalled"
                ValueData = "1"
                ValueType = "Dword"
                PsDscRunAsCredential = $SPSetupAccount
            }
        }
        if ($ConfigurationData.NonNodeData.DisableIEESC.User)
        {
            Registry DisableIEESCUser
            {
                Ensure = "Present"
                Key = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
                ValueName = "IsInstalled"
                ValueData = "0"
                ValueType = "Dword"
                PsDscRunAsCredential = $SPSetupAccount
            }
        }Else
        {
            Registry EnableIEESCUser
            {
                Ensure = "Present"
                Key = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
                ValueName = "IsInstalled"
                ValueData = "1"
                ValueType = "Dword"
                PsDscRunAsCredential = $SPSetupAccount
            }
        }
                 
        WindowsFeature WebAdministration 
        { 
            Ensure = 'Present'
            PsDscRunAsCredential = $SPSetupAccount
            Name   = 'Web-Mgmt-Tools'             
        }

        xTimeZone WindowsServerTimeZone
        {
            TimeZone = $Node.TimeZone
            IsSingleInstance = 'Yes'
        }

        File LocalScratchFolder 
        {
            Type = 'Directory'
            DestinationPath = $ConfigurationData.NonNodeData.DSCConfig.DSCLocalFolder
            PsDscRunAsCredential = $SPSetupAccount
            Ensure = "Present"
        }

        # Create folders on each server
        $ConfigurationData.NonNodeData.CreateFolders | ForEach {
            $Name = $_.Path
            $Name = ($Name.Split("\"))[1]
            File $Name
            {
                Type = 'Directory'
                DestinationPath = $_.Path
                PsDscRunAsCredential = $SPSetupAccount
                Ensure = "Present"
            }
        }

        ForEach($Item in $ConfigurationData.NonNodeData.FilesandFolders)
        {
            $Name = $Item.Source
            File $Name
            {
                Ensure = $Item.Ensure
                Type = $Item.Type
                Recurse = $Item.Recurse
                SourcePath = $Item.Source
                DestinationPath = $Item.Destination
                Force = $Item.Force
                MatchSource = $Item.MatchSource
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[WindowsFeature]WebAdministration"
            }
        }

        # Disable SSL3 and TLS based on version of SharePoint
        # https://thesharepointfarm.com/2016/04/enabling-tls-1-2-support-sharepoint-server-2016/
        # https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in

        xWebAppPool RemoveDotNet2Pool         { Name = ".NET v2.0";            Ensure = "Absent";}
        xWebAppPool RemoveDotNet2ClassicPool  { Name = ".NET v2.0 Classic";    Ensure = "Absent";}
        xWebAppPool RemoveDotNet45Pool        { Name = ".NET v4.5";            Ensure = "Absent";}
        xWebAppPool RemoveDotNet45ClassicPool { Name = ".NET v4.5 Classic";    Ensure = "Absent";}
        xWebAppPool RemoveClassicDotNetPool   { Name = "Classic .NET AppPool"; Ensure = "Absent";}
        xWebAppPool RemoveDefaultAppPool      { Name = "DefaultAppPool";       Ensure = "Absent";}
        xWebSite    RemoveDefaultWebSite      { Name = "Default Web Site";     Ensure = "Absent"; PhysicalPath = "C:\inetpub\wwwroot";}

        # No longer relevant as best practice is to use DNS
            <#
                    #setup SQL aliases
            foreach ($SQL in $ConfigurationData.NonNodeData.SharePointFarm.SQLServers)
            {

                Registry "$($SQL.Alias)-x86"
                {
                    Ensure = "Present"
                    Key = "HKLM:\Software\Microsoft\MSSQLServer\Client\ConnectTo"
                    ValueName = $SQL.Alias
                    ValueData = "DBMSSOCN,$($SQL.DNSname),$($SQL.Port)"
                }

                Registry "$($SQL.Alias)-x64"
                {
                    Ensure = "Present"
                    Key = "HKLM:\Software\Wow6432Node\Microsoft\MSSQLServer\Client\ConnectTo"
                    ValueName = $SQL.Alias
                    ValueData = "DBMSSOCN,$($SQL.DNSname),$($SQL.Port)"
                }

            }
            #>

        #Set Ciphers as per V-59969 and V-59971
        if ($Node.ServerHardening.Ciphers.Present) 
        {
            Script SetV59965v59971Ciphers
            {
                GetScript = {
                    Return @{Result = [string]$(Get-TlsCipherSuite)}
                }
                SetScript = {
                    #Remove all default ciphers
                    Get-Tlsciphersuite | ForEach-Object { $_ | Disable-TlsCipherSuite }
                    #Add desired ciphers
                    $Ciphers = $Using:Node.ServerHardening.Ciphers.Value
                    $Ciphers | ForEach-object { $_ | Enable-TlsCipherSuite }
                }
                TestScript = {
                    $Ciphers = $Using:Node.ServerHardening.Ciphers.Value
                    $Return = $True
                    $Ciphers | ForEach-Object {
                        $IsitThere = $null
                        $IsitThere = $_ | Get-TlsCipherSuite
                        If(!$IsitThere)
                        { $Return = $false }
                    }
                    Return $Return
                }
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[WindowsFeature]WebAdministration"
            }
        }

        If($Node.ServerHardening.EnsureSetupAccountPermission -and $Node.ServerHardening.EnsureFarmAdminAccountPermission)
        {
            Group AddFarmSetupAccttoWSSADMINWPG
            {
                Ensure = "Present"
                GroupName = "WSS_ADMIN_WPG"
                MembersToInclude = @($ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.SetupAccount,$ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.FarmAccount)
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[SPInstall]InstallSP2016"
            }
        }Else
        {
            if($Node.ServerHardening.EnsureSetupAccountPermission)
            {
                Group AddSetupAccttoWSSADMINWPG
                {
                    Ensure = "Present"
                    GroupName = "WSS_ADMIN_WPG"
                    MembersToInclude = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.SetupAccount
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn = "[SPInstall]InstallSP2016"
                }
            }
            if($Node.ServerHardening.EnsureFarmAdminAccountPermission)
            {
                Group AddFarmAccttoWSSADMINWPG
                {
                    Ensure = "Present"
                    GroupName = "WSS_ADMIN_WPG"
                    MembersToInclude = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.FarmAccount
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn = "[SPInstall]InstallSP2016"
                }
            }
        }

        if($Node.ServerHardening.EnsureSetupAccountPermission)
        {
            Group AddSetupAccttoLocalAdmin
            {
                Ensure = "Present"
                GroupName = "Administrators"
                MembersToInclude = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.SetupAccount
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[SPInstall]InstallSP2016"
            }
            
            Group AddSetupAccttoIISWPG
            {
                Ensure = "Present"
                GroupName = "IIS_WPG"
                MembersToInclude = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.SetupAccount
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[SPInstall]InstallSP2016"
            }
        }

        if($Node.ServerHardening.EnsureFarmAdminAccountPermission)
        {           
            Group AddFarmAccttoWSSRESTRICTEDWPG
            {
                Ensure = "Present"
                GroupName = "WSS_RESTRICTED_WPG"
                MembersToInclude = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.FarmAccount
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[SPInstall]InstallSP2016"
            }

            Group AddFarmAccttoWSSWPG
            {
                Ensure = "Present"
                GroupName = "WSS_WPG"
                MembersToInclude = $ConfigurationData.NonNodeData.SharePoint.ServiceAccounts.FarmAccount
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn = "[SPInstall]InstallSP2016"
            }
        }

        # Starting services if MINRole is set to Custom
        if ($Node.MinRole -eq 'Custom') 
        {
            # Common Services across all nodes
            SPServiceInstance ClaimsToWindowsTokenServiceInstance
            {  
                Name                 = "Claims to Windows Token Service"
                Ensure               = "Present"
                PsDscRunAsCredential = $SPSetupAccount
                DependsOn            = "[SPInstall]InstallSP2016"
            }

            $FarmWaitTask = "[SPServiceInstance]ClaimsToWindowsTokenServiceInstance"

            # Distributed cache
            if ($Node.CustomServices.DistributedCache -eq $true) 
            {
                $AllDCacheNodes = $AllNodes | Where-Object { $_.MinRole -eq 'Custom' -or $_.CustomServices.DistributedCache -eq $true }
                $CurrentDcacheNode = [Array]::IndexOf($AllDCacheNodes, $Node)

                if ($Node.NodeName -ne $AllNodes.Where{$_.FirstServer}.NodeName) 
                {
                    # Node is not the first app server so won't have the dependency for the service account
                    WaitForAll WaitForServiceAccount 
                    {
                        ResourceName         = "[SPManagedAccount]ServicePoolManagedAccount"
                        NodeName             = $FirstAppServer
                        RetryIntervalSec     = 30
                        RetryCount           = 5
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = $FarmWaitTask 
                    }
                    $DCacheWaitFor = "[WaitForAll]WaitForServiceAccount"
                }Else
                {
                    $DCacheWaitFor = "[SPManagedAccount]ServicePoolManagedAccount"
                }

                if ($CurrentDcacheNode -eq 0) 
                {
                    # The first distributed cache node doesn't wait on anything
                    SPDistributedCacheService EnableDistributedCache
                    {
                        Name                 = "AppFabricCachingService"
                        Ensure               = "Present"
                        CacheSizeInMB        = $ConfigurationData.NonNodeData.SharePoint.DCache.CacheSizeInMB
                        ServiceAccount       = $ServicePoolManagedAccount.UserName
                        CreateFirewallRules  = $true
                        ServerProvisionOrder = $AllDCacheNodes.NodeName
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = @($FarmWaitTask,$DCacheWaitFor)
                    }
                }Else 
                {
                    # All other distributed cache nodes depend on the node previous to it
                    $previousDCacheNode = $AllDCacheNodes[$CurrentDcacheNode - 1]
                    WaitForAll WaitForDCache
                    {
                        ResourceName         = "[SPDistributedCacheService]EnableDistributedCache"
                        NodeName             = $previousDCacheNode.NodeName
                        RetryIntervalSec     = 60
                        RetryCount           = 60
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = $FarmWaitTask
                    }
                    SPDistributedCacheService EnableDistributedCache
                    {
                        Name                 = "AppFabricCachingService"
                        Ensure               = "Present"
                        CacheSizeInMB        = $ConfigurationData.NonNodeData.SharePoint.DCache.CacheSizeInMB
                        ServiceAccount       = $ServicePoolManagedAccount.UserName
                        CreateFirewallRules  = $true
                        ServerProvisionOrder = $AllDCacheNodes.NodeName
                        PsDscRunAsCredential = $SPSetupAccount
                        DependsOn            = "[WaitForAll]WaitForDCache"
                    }
                }
            }
            If ($Node.CustomServices.AppManagement -eq $true) 
            {
                SPServiceInstance AppManagementService 
                {
                    Name                 = "App Management Service"
                    Ensure               = "Present"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }Else
            {
                SPServiceInstance AppManagementService 
                {
                    Name                 = "App Management Service"
                    Ensure               = "Absent"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }
            If ($Node.CustomServices.BCS -eq $true) 
            {
                SPServiceInstance BCSServiceInstance
                {  
                    Name                 = "Business Data Connectivity Service"
                    Ensure               = "Present"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }Else
            {
                SPServiceInstance BCSServiceInstance
                {  
                    Name                 = "Business Data Connectivity Service"
                    Ensure               = "Absent"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }
            If ($Node.CustomServices.SubscriptionSettings -eq $true) 
            {
                SPServiceInstance SubscriptionSettingsService
                {  
                    Name                 = "Microsoft SharePoint Foundation Subscription Settings Service"
                    Ensure               = "Present"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }Else
            {
                SPServiceInstance SubscriptionSettingsService
                {  
                    Name                 = "Microsoft SharePoint Foundation Subscription Settings Service"
                    Ensure               = "Absent"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }
            If ($Node.CustomServices.SecureStore -eq $true) 
            {
                 SPServiceInstance SecureStoreService
                {  
                    Name                 = "Secure Store Service"
                    Ensure               = "Present"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }Else
            {
                SPServiceInstance SecureStoreService
                {  
                    Name                 = "Secure Store Service"
                    Ensure               = "Absent"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }
            If ($Node.CustomServices.UserProfile -eq $true) 
            {
                SPServiceInstance UserProfileService
                {  
                    Name                 = "User Profile Service"
                    Ensure               = "Present"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }Else
            {
                SPServiceInstance UserProfileService
                {  
                    Name                 = "User Profile Service"
                    Ensure               = "Absent"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }
            If ($Node.CustomServices.WorkFlowTimer -eq $true) 
            {
                SPServiceInstance WorkflowTimerService 
                {
                    Name                 = "Microsoft SharePoint Foundation Workflow Timer Service"
                    Ensure               = "Present"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }Else
            {
                SPServiceInstance WorkflowTimerService 
                {
                    Name                 = "Microsoft SharePoint Foundation Workflow Timer Service"
                    Ensure               = "Absent"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }
            if ($Node.CustomServices.WebFrontEnd -eq $true) 
            {
                SPServiceInstance WebApplicationService
                {  
                    Name                 = "Microsoft SharePoint Foundation Web Application"
                    Ensure               = "Present"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }Else
            {
                SPServiceInstance WebApplicationService
                {  
                    Name                 = "Microsoft SharePoint Foundation Web Application"
                    Ensure               = "Absent"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }
            if ($Node.CustomServices.ManagedMetadata -eq $true) 
            {
                SPServiceInstance ManagedMetadataServiceInstance
                {  
                    Name                 = "Managed Metadata Web Service"
                    Ensure               = "Present"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }Else
            {
                SPServiceInstance ManagedMetadataServiceInstance
                {  
                    Name                 = "Managed Metadata Web Service"
                    Ensure               = "Absent"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }
            if ($Node.CustomServices.VisioGraphics -eq $true) 
            {
                SPServiceInstance VisioGraphicsService
                {  
                    Name                 = "Visio Graphics Service"
                    Ensure               = "Present"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }Else
            {
                SPServiceInstance VisioGraphicsService
                {  
                    Name                 = "Visio Graphics Service"
                    Ensure               = "Absent"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }
            if ($Node.CustomServices.Search -eq $true) 
            {
                SPServiceInstance SearchService 
                {  
                    Name                 = "SharePoint Server Search"
                    Ensure               = "Present"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }Else
            {
                SPServiceInstance SearchService 
                {  
                    Name                 = "SharePoint Server Search"
                    Ensure               = "Absent"
                    PsDscRunAsCredential = $SPSetupAccount
                    DependsOn            = $FarmWaitTask
                }
            }      
        }

        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
        }   
    }
}
# *****IGNORE EVERYTHING BELOW THIS LINE IT IS ALL COMMENTED OUT********

<#
Script BindSSLCert
        {            
            GetScript = {            
                Return @{Result = [string]$(Get-ChildItem "Cert:\LocalMachine\My")}            
            }                       
            TestScript = {            
                Install-WindowsFeature web-mgmt-console
                # Grab the IP based on the interface name, which is previously set in DSC
                $IP1  = (Get-NetIPAddress -addressfamily ipv4 -InterfaceAlias $($Using:Node.VLAN)).IPAddress
                # Find out if we've got anything bound on this IP for port 443
                $Bindcheck = get-webbinding -name "Apps" -IPAddress $IP1 -Port 443
                $BindcheckWildcard = get-webbinding -name "Apps" | where-object { $_.BindingInformation -eq "*:80:"}
                # If site exists
                    if (Test-Path "IIS:\Sites\Apps")
                    { 
                        # if log file setting correct
                        if ((Get-ItemProperty "IIS:\Sites\Apps" -name logfile).directory -ieq "E:\inetpub\logs\AppsSite")
                           {
                                   # if IP bound on port 443
                                   if ($bindcheckhttps)
                                   { 
                                       #if SSL certificate bound
                                       if (Test-path "IIS:\SslBindings\$ip1!443")
                                       {
                                            # wildcard binding check for Apps
                                            if (-not ($bindcheckwildcard)) {
                                                Return $true
                                            }Else
                                            {
                                                Return $false
                                            }
                                       }
                                       else
                                       {
                                           Return $false
                                       }
                                   }
                                   else
                                   {
                                       Write-Verbose "IP not bound on 443 for Apps."
                                       Return $false
                                   }
                           }
                            else 
                            {
                               Write-Verbose "Log file path is not set correctly"
                               Return $false
                            } 
                   }
                   else
                   {
                       Write-Verbose "Apps site does not exist"
                       Return $false
                   }
                }    
 
            # Returns nothing            
            SetScript = {
                $SiteName = 'mywebsite'
                
                Invoke-SPDscCommand -ScriptBlock {
                    Install-WindowsFeature web-mgmt-console
                    $Binding = Get-WebBinding -Name $SiteName -Protocol "https"
                    $Binding.AddSslCertificate($newCert.GetCertHashString(), "My")
                } -Arguments $SiteName $SiteUrl
            } 
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn = ""
        }
#>
     #   $searchNode = ($AllNodes | Where-Object { $_.MinRole -eq 'Search' -or $_.MinRole -eq 'ApplicationWithSearch' -or ($_.MinRole -eq 'Custom' -and $_.CustomServices.Search) -or $_.MinRole -eq 'SingleServer' } | Select-Object -First 1)           
             <#       $ConfigurationData.NonNodeData.SharePoint.Search.SearchContentSource | ForEach-Object{
                        if(!($_.IncrementalSchedule))
                        {
                            $Incremental_Schedule = $null
                        }Else
                        {                                                                                                                                        
                            Switch($_.IncrementalSchedule.ScheduleType)
                            {
                                "Daily" {
                                            $Incremental_Schedule = MSFT_SPSearchCrawlSchedule {
                                                ScheduleType = "Daily" 
                                                StartHour = $_.IncrementalSchedule.StartHour
                                                StartMinute = $_.IncrementalSchedule.StartMinute
                                                CrawlScheduleRepeatDuration = $_.IncrementalSchedule.CrawlScheduleRepeatDuration
                                                CrawlScheduleRepeatInterval = $_.IncrementalSchedule.CrawlScheduleRepeatInterval
                                            }
                                        }
                               "Weekly" {
                                            $Incremental_Schedule = MSFT_SPSearchCrawlSchedule {
                                                ScheduleType = "Weekly"
                                                CrawlScheduleDaysofWeek = $_.IncrementalSchedule.CrawlScheduleDaysOfWeek
                                                StartHour = $_.IncrementalSchedule.StartHour
                                                StartMinute = $_.IncrementalSchedule.StartMinute
                                                CrawlScheduleRepeatDuration = $_.IncrementalSchedule.CrawlScheduleRepeatDuration
                                                CrawlScheduleRepeatInterval = $_.IncrementalSchedule.CrawlScheduleRepeatInterval
                                            }
                                        }
                              "Monthly" {
                                            $Incremental_Schedule = MSFT_SPSearchCrawlSchedule {
                                                ScheduleType = "Monthly"
                                                CrawlScheduleMonthsofYear = $_.IncrementalSchedule.CrawlScheduleMonthsofYear
                                                StartHour = $_.IncrementalSchedule.StartHour
                                                StartMinute = $_.IncrementalSchedule.StartMinute
                                                CrawlScheduleRepeatDuration = $_.IncrementalSchedule.CrawlScheduleRepeatDuration
                                                CrawlScheduleRepeatInterval = $_.IncrementalSchedule.CrawlScheduleRepeatInterval
                                            }
                                        }
                            }
                        }
                        if(!($_.FullSchedule))
                        {
                            $Full_Schedule = $null
                        }Else
                        {                                                                                                                                    
                            Switch($_.FullSchedule.ScheduleType)
                            {
                                "Daily" {
                                            $Full_Schedule = MSFT_SPSearchCrawlSchedule {
                                                ScheduleType = "Daily" 
                                                StartHour = $_.FullSchedule.StartHour
                                                StartMinute = $_.FullSchedule.StartMinute
                                                CrawlScheduleRepeatDuration = $_.FullSchedule.CrawlScheduleRepeatDuration
                                                CrawlScheduleRepeatInterval = $_.FullSchedule.CrawlScheduleRepeatInterval
                                            }
                                        }
                               "Weekly" {
                                            $Full_Schedule = MSFT_SPSearchCrawlSchedule {
                                                ScheduleType = "Weekly"
                                                CrawlScheduleDaysOfWeek = $_.FullSchedule.CrawlScheduleDaysOfWeek
                                                StartHour = $_.FullSchedule.StartHour
                                                StartMinute = $_.FullSchedule.StartMinute
                                                CrawlScheduleRepeatDuration = $_.FullSchedule.CrawlScheduleRepeatDuration
                                                CrawlScheduleRepeatInterval = $_.FullSchedule.CrawlScheduleRepeatInterval
                                            }
                                        }
                              "Monthly" {
                                            $Full_Schedule = MSFT_SPSearchCrawlSchedule {
                                                ScheduleType = "Monthly"
                                                CrawlScheduleMonthsofYear = $_.FullSchedule.CrawlScheduleMonthsofYear
                                                StartHour = $_.FullSchedule.StartHour
                                                StartMinute = $_.FullSchedule.StartMinute
                                                CrawlScheduleRepeatDuration = $_.FullSchedule.CrawlScheduleRepeatDuration
                                                CrawlScheduleRepeatInterval = $_.FullSchedule.CrawlScheduleRepeatInterval
                                            }
                                        }
                            }
                        }
                        SPSearchContentSource $_.Name
                        {
                            Name                 = $_.Name
                            ServiceAppName       = $_.ServiceAppName
                            ContentSourceType    = $_.ContentSourceType
                            Addresses            = $_.Addresses
                            CrawlSetting         = $_.CrawlSetting
                            ContinuousCrawl      = $_.ContinuousCrawl
                            IncrementalSchedule  = $Incremental_Schedule
                            FullSchedule         = $Full_Schedule
                            Priority             = $_.Priority
                            Ensure               = "Present"
                            PsDscRunAsCredential = $SPSetupAccount
                            DependsOn            = "[SPSearchTopology]SearchTopology"
                        }
                    }#>
 <#      if($UPASyncConnectAccounts -or ($UPASyncConnectAccounts).count -gt 0)
            {
                if($ConfigurationData.NonNodeData.SharePoint.Version -eq 2013)
                {
                    foreach($UPASyncConnection in $ConfigurationData.NonNodeData.SharePoint.UserProfileService.UserProfileSyncConnection) {
                        $ConnectionAccountCreds = $UPASyncConnectAccounts | where {$_.UserName -eq $UPASyncConnection.ConnectionUsername}
                        SPUserProfileSyncConnection $UPASyncConnection.Name
                        {
                            UserProfileService = $ConfigurationData.NonNodeData.SharePoint.UserProfileService.Name
                            Forest = $UPASyncConnection.Forest
                            Name = $UPASyncConnection.Name
                            ConnectionCredentials = $ConnectionAccountCreds
                            Server = $UPASyncConnection.Server
                            UseSSL = $UPASyncConnection.UseSSL
                            IncludedOUs = $UPASyncConnection.IncludedOUs
                            ExcludedOUs = $UPASyncConnection.ExcludedOUs
                            Force = $UPASyncConnection.Force
                            ConnectionType = "ActiveDirectory"
                            PsDscRunAsCredential = $SPSetupAccount
                            DependsOn = "[SPUserProfileServiceApp]UserProfileServiceApp"
                        }
                    }
                }
                Else
                {
                }
            }#>
#incoming email
<#
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * ##Function - Configure Incoming Email settings in SharePoint farm## Author - Deepak Solanki## Checks to ensure that Microsoft.SharePoint.Powershell is loaded,  
    if not, adding pssnapin## Configure Incoming Email settings in SharePoint farm# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #Add SharePoint Add - ins  
Add - PSSnapin Microsoft.SharePoint.PowerShell - erroraction SilentlyContinue#  
if snapin is not installed then use this method  
    [Void][System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint")  
  
  
Write - Host "Script started to Configure Incoming Email."  
 
 
#  
Variables to get config values  
    [boolean] $Enabled = $true;  
[boolean] $UseAutomaticSettings = $false;  
[boolean] $UseDirectoryManagementService = $true;  
[boolean] $RemoteDirectoryManagementService = $false;  
$ServerAddress = "EXCHANGE.DOMAIN.COM";  
[boolean] $DLsRequireAuthenticatedSenders = $true;  
[boolean] $DistributionGroupsEnabled = $true;  
$ServerDisplayAddress = "sharepoint.company.com";  
$DropFolder = "c:\inetpub\mailroot\drop";  
 
#  
Test the drop folder location exists before proceeding with any changes  
$dropLocationTest = Get - Item $DropFolder - ErrorAction SilentlyContinue  
if ($dropLocationTest - eq $null) {  
    Throw "The drop folder location $DropFolder does not exist - please create the path and try the script again."  
}  
 
#  
Configuring Incoming E - mail Settings  
try {  
    $type = "Microsoft SharePoint Foundation Incoming E-Mail"  
    $svcinstance = Get - SPServiceInstance | where {  
        $_.TypeName - eq $type  
    }  
    $inmail = $svcinstance.Service  
  
  
    if ($inmail - ne $null) {  
        Write - Log "Configuring Incoming E-mail Settings."#  
        Enable sites on this server to receive e - mail  
        $inmail.Enabled = $Enabled  
 
        # Automatic Settings mode  
        $inmail.UseAutomaticSettings = $UseAutomaticSettings  
 
        # Use the SharePoint Directory Management Service to create distribution groups  
        $inmail.UseDirectoryManagementService = $UseDirectoryManagementService  
 
        # Use remote: Directory Management Service  
        $inmail.RemoteDirectoryManagementService = $RemoteDirectoryManagementService  
 
        # SMTP mail server  
        for incoming mail  
        $inmail.ServerAddress = $ServerAddress  
 
        # Accept messages from authenticated users only  
        $inmail.DLsRequireAuthenticatedSenders = $DLsRequireAuthenticatedSenders  
 
        # Allow creation of distribution groups from SharePoint sites  
        $inmail.DistributionGroupsEnabled = $DistributionGroupsEnabled  
 
        # E - mail server display address  
        $inmail.ServerDisplayAddress = $ServerDisplayAddress  
 
        # E - mail drop folder  
        $inmail.DropFolder = $DropFolder;  
  
        $inmail.Update();  
        Write - Host "Incoming E-mail Settings completed."  
    }  
}#  
Report  
if there is a problem setting Incoming Email  
catch {  
    Write - Host "There was a problem setting Incoming Email: $_"  
}  
#>