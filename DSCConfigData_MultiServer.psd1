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

@{
    AllNodes = @(
        @{
            NodeName                    = "*"
            DisableIISLoopbackCheck     = $true
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
            InstallPrereqs              = $true
            InstallSharePoint           = $true
            TimeZone                    = "Eastern Standard Time"
            ServerHardening = @{
                #v59937 = $true
                #v59939 = $true
                #v59943 = $true
                #v59975 = $true
                #v59979 = $true # TODO: Implement in DSCConfig import of cert and binding of SSL
                Ciphers = @{ #TODO: Configure TLS Cyphers (Tested....works)
                    Present = $true
                    Value = @("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P521","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P521","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P521","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P521","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P521","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P384","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384_P256","TLS_RSA_WITH_AES_256_GCM_SHA384","TLS_RSA_WITH_AES_128_GCM_SHA256","TLS_DHE_RSA_WITH_AES_256_GCM_SHA384","TLS_DHE_RSA_WITH_AES_256_CBC_SHA")
                }
                #v59981 = $true # TODO  Not sure how to enforce, will provide a way to set IP in binding
                EnsureSetupAccountPermission = $true # TODO: Verify that on each server setup account is a member of only Local Admin, WSS_ADMIN_WPG, and IIS_WPG (Tested...works)
                EnsureFarmAdminAccountPermission = $true # TODO: Verify that on each server farm admin account is a member of only WSS_RESTRICTED_WPG, WSS_ADMIN_WPG, and WSS_WPG (Tested...works)
            }
        },
        @{ 
            NodeName                    = "SP2016APP01"
            FirstServer                 = $true
            MinRole                     = "Custom"#https://technet.microsoft.com/en-us/library/mt667910(v=office.16).aspx, https://msdn.microsoft.com/en-us/library/office/microsoft.sharepoint.administration.spserverrole.aspx
            CentralAdminHost            = $true
            PowerShellServer            = $true
            CustomServices = @{  
                WebFrontEnd             = $false
                DistributedCache        = $false
                AppManagement           = $False
                BCS                     = $False
                SubScriptionSettings    = $false
                SecureStore             = $False
                UserProfile             = $true
                WorkFlowTimer           = $false
                ManagedMetadata         = $true
                VisioGraphics           = $false
                Search                  = $true
            }
          },
          @{ 
            NodeName                    = "SP2016APP02"
            FirstServer                 = $false
            MinRole                     = "ApplicationWithSearch"#https://technet.microsoft.com/en-us/library/mt667910(v=office.16).aspx
            CentralAdminHost            = $false
            PowerShellServer            = $false
            CustomServices = @{  
                WebFrontEnd             = $false
                DistributedCache        = $false
                AppManagement           = $False
                BCS                     = $False
                SubScriptionSettings    = $false
                SecureStore             = $False
                UserProfile             = $false
                WorkFlowTimer           = $false
                ManagedMetadata         = $false
                VisioGraphics           = $false
                Search                  = $false
            }
          },
        @{ 
            NodeName                    = "SP2016WFE01"
            FirstServer                 = $false
            MinRole                     = "WebFrontEndWithDistributedCache"
            CentralAdminHost            = $false
            PowerShellServer            = $false
            CustomServices = @{  
                WebFrontEnd             = $false
                DistributedCache        = $false
                AppManagement           = $False
                BCS                     = $False
                SubScriptionSettings    = $false
                SecureStore             = $False
                UserProfile             = $false
                WorkFlowTimer           = $false
                ManagedMetadata         = $false
                VisioGraphics           = $false
                Search                  = $false
            }
          },
          @{ 
                NodeName                    = "SP2016WFE02"
                FirstServer                 = $false
                MinRole                     = "WebFrontEndWithDistributedCache"
                CentralAdminHost            = $false
                PowerShellServer            = $false
                CustomServices = @{  
                    WebFrontEnd             = $false
                    DistributedCache        = $false
                    AppManagement           = $False
                    BCS                     = $False
                    SubScriptionSettings    = $false
                    SecureStore             = $False
                    UserProfile             = $false
                    WorkFlowTimer           = $false
                    ManagedMetadata         = $false
                    VisioGraphics           = $false
                    Search                  = $false
                }
            }
            <#,
          @{ 
            NodeName                    = "OOS01"
            OOSMasterServer                 = $True
            Role                     = "OOS" #OOS will tell script to build an Office Online server
            OOSRole            = "All" #Set to All unless you have over 50 servers in OOS farm https://docs.microsoft.com/en-us/powershell/module/officewebapps/new-officewebappsmachine?view=officewebapps-ps
            },
          @{ 
            NodeName                    = "OOS02"
            OOSMasterServer                 = $false
            Role                     = "OOS"
            OOSRole            = "All" #Set to All unless you have over 50 servers in OOS farm https://docs.microsoft.com/en-us/powershell/module/officewebapps/new-officewebappsmachine?view=officewebapps-ps
          } #>
    )
    NonNodeData = @{
        FarmHardening = @{
            BrowserFileHandling = $True #TODO: Configure browser file handling (Tested...works)
            RMS = @{    #This covers v-59945 and v-59947 as well (Tested - Works)
                Present = $true
                RMSUseAD = $true
                RMSCertServer = ""
            }
            BlockedFileList = @{ # (Tested - Works)
                Present = $true
                Value = @("ashx","asmx","json","soap","svc","xamlx")
            }
            SetSiteCollectionAudit = @{ # TODO: Programatically turn on Site Auditing on all Site Collections (Tested....works)
                Present = $true
                AuditElements = "All" #@("Delete","Update") #Provide array of items https://docs.microsoft.com/en-us/dotnet/api/microsoft.sharepoint.spauditmasktype?view=sharepoint-server
                DaystoTrim = 30
            }
            ####### Currently only does one solution need to make it so that it can do multiple solutions
            FarmSolutions = @( # TODO: Will deploy or retract the solution you provide it (Tested...works)
                @{ 
                    Present = $false
                    SolutionName = "ESPS_DoDBanner.wps"
                    SolutionPath = "\\DSC01\DSCShare\Solutions"
                    VersionNumber = "1.0.0"
                } 
            )
            ULSLogBaseLevel = @{ # TODO: Need to test
                Present = $false # TODO: Set ULS log levels to a base level, http://nikcharlebois.com/setting-saving-restoring-logging-level-for-sharepoint-using-powershell/
                Categories = @(
                    @{
                        AreaName = "SharePoint Foundation" #Using wildcard will include all subareas
                        SubAreaName = "*" #Using wildcard * will include all subareas
                        TraceLevel = "VerboseEx" # "None","Unexpected","Monitorable","High","Medium","Verbose","VerboseEx","Default"
                        EventLevel = "Verbose" # "None","ErrorCritical","Error","Warning","Information","Verbose","Default"
                    },
                    @{
                        AreaName = "SharePoint Server" #Using wildcard will include all subareas
                        SubAreaName = "Database" #Using wildcard * will include all subareas
                        TraceLevel = "High" # "None","Unexpected","Monitorable","High","Medium","Verbose","VerboseEx","Default"
                        EventLevel = "Information" # "None","ErrorCritical","Error","Warning","Information","Verbose","Default"
                    }
                )           
            }
            SetIISProperties = $false # TODO: Make sure following is set for each webapp Connection Time-Out, Maximum Bandwidth, Maximum Concurrent Connections Does not include CA
            BlockAnonymous = @{
                Present = $true
                WhitelistAnnonymousWebApp = @("http://ecm.weaver.ad")  # TODO: Allow only those webApps in Whitelist to allow annonymous (Tested....works)(Whitelist tested...works)
            }
            BlockOnlineWebPartGallery = $true # TODO: Prevent users from accessing Online Web Part Gallery (Tested...works)
      <#
            v59997 = $false # TODO: Verify that farm Admin account is a member of only Domain Users group (Will need to create script resource for this)
            v59999 = $false # TODO: Verify that farm admin account is only Server Roles Public, dbcreator, and Securityadmin as well User Mapping:Public and DB_Owner on all SharePoint Databases (Not sure how to do this in DSC)
            v60001 = $false # TODO: Verify that setup account is a memeber of only Domain Users group (Will need to create script resource for this)
            v60003 = $false # TODO: Verify that setup account is only Server Roles Public, dbcreator, and Securityadmin as well User Mapping:Public and DB_Owner on all SharePoint Databases (Not sure how to do this in DSC)
      #>
            SetSPAntiVirus = $true # TODO: Set the following for SP Antivirus Scan documents on upload, Scan documents on download, Attempt to clean infected documents. (Tested....works)
        }
        DSCConfig = @{
            DSCConfigPath               = "C:\_DSCConfig"
            #DSCConfigModulePath         = "C:\_DSCConfig\Modules" 
            DSCConfigServiceEndPoint    = "https://dscserver.weaver.ad:8080/PSDSCPullServer.svc"  #Url for DSC service
            DSCConfigSharePath          = "\\DSC01\DSCConfig" #Removed \Configuration
            DSCConfigModuleOnline       = $true                 #If the DSC server has internet access set this to true
            DSCLocalFolder              = "C:\_DSCOutput"       #This must exist on client machines
           # DSCConfigModuleShare        = "\\dsc03\DSCConfig\Modules"
            DSCServicePhysicalPath      = "$env:SystemDrive\inetpub\DSCPullServer" 
            DSCUseSecurityBestPractices = $true
            DSCAcceptSelfSignedCertificates = $true
            DSCConfigRegistryKey = "b2d9d288-fd87-4b26-9761-e211fd9a13d7"
            DSCCOnfigRegistryKeyFile = "C:\_RegistrationKey"     # This folder should be seperate from others, DSC process will create
            InstalledModules = @("OfficeOnlineServerDSC","NetworkingDSC","xTimezone","SQLServerDSC","CertificateDsc","xSystemSecurity","xPendingReboot","SharePointDsc","xWebAdministration","xCredSSP","xDscDiagnostics","PSDscResources")
        }
        DisableIEESC = @{
            Admin = $true #If true will disable IE hardening for admins, if false will set hardening
            User = $true #If true will disable IE hardening for users, if false will set hardening
        }
        CreateFolders = @(
            @{
                Path = "C:\Scripts"
            },
            @{
                Path = "C:\Weaver"
            }
        )
        FilesandFolders = @(
       <#     @{
                Type = "Directory" # Enter Directory or File
                Ensure = "Present" # If you set to Present it will create, if set to absent it will delete
                Recurse = $true # if $true ensures presence of subdirectories, too
                Source = "C:\Users\Public\Documents\DSCDemo\DemoSource\"
                Destination = "C:\Users\Public\Documents\DSCDemo\DemoDestination"
                Force = $true
                MatchSource = $false    # Will match the source and destination folder when DSC runs
            },
            @{
                Type = "Directory" # Enter Directory or File
                Ensure = "Present" # If you set to Present it will create, if set to absent it will delete
                Recurse = $true # if $true ensures presence of subdirectories, too
                Source = "C:\Users\Public\Documents\DSCDemo\DemoSource\"
                Destination = "C:\Users\Public\Documents\DSCDemo\DemoDestination"
                Force = $true
                MatchSource = $True
            } #>
        )
        DomainDetails = @{
            DomainName                  = "weaver.ad"
            NetbiosName                 = "weaver"
        }
        SQLServer = @{
            SQLInstance = "SharePoint"
            ContentDatabaseServer       = "sqlalias.weaver.ad"
            SearchDatabaseServer        = "sqlalias.weaver.ad"
            ServiceAppDatabaseServer    = "sqlalias.weaver.ad"
            FarmDatabaseServer          = "sqlalias.weaver.ad"
        }
        OfficeOnline = @{
            Binding = @(
                @{
                    Zone = "Internal-HTTP" #Internal-HTTP, Internal-HTTPS, External-HTTP, External-HTTPS
                    ServerName = "" #If you leave it blank we will set to MasterServer
                },
                @{
                    Zone = "External-HTTPS" #Internal-HTTP, Internal-HTTPS, External-HTTP, External-HTTPS
                    ServerName = "OOS.collab.weaver.com" #If you leave it blank we will set to MasterServer
                }
            )
            Installation = @{
                BinaryDir = "\\dsc01\DSCShare\OOSBinaries"
            }
            Firewall = @{
                DisplayName = "Office Online Server Inter-Farm Communication"
                CustomGroup = "OOS Firewall Group"
                Enabled = $true
                Direction = "Inbound" 
                Protocol = "TCP"
                LocalPort = ("80", "443", "808")
                Profile = "Domain"
            } #https://docs.microsoft.com/en-us/powershell/module/officewebapps/set-officewebappsfarm?view=officewebapps-ps
            AllowCEIP = $true #Enables Customer Experience Improvement Program (CEIP) reporting on all servers in the Office Web Apps Server farm
            AllowHTTP = $false #Indicates that IIS sites should be provisioned on port 80 for HTTP access. Use AllowHTTP only in environments where all computers require IPSEC (full encryption) or in test environments that do not contain sensitive files.
            CacheLocation = "C:\Cache" #Specifies the location of the global disk cache that is used to store rendered image files.
            CacheSizeinGB = 20 #Specifies the maximum size of the global disk cache in gigabytes.
            CertificateName = $null #Specifies the friendly name of the certificate that Office Web Apps Server uses to create HTTPS bindings.
            ClipartEnabled = $true #Enables support for inserting clip art from Office.com into Office documents. This feature requires server-to-web communication, configured either directly or by using a proxy that you specify by using the Proxy parameter.
            DocumentInfoCacheSize = 500 #Specifies the maximum number of document conversion records that are stored in a memory cache.
            EditingEnabled = $true #Enables support for editing in the browser. The default is False. Only set to True if you have the appropriate licensing to use the editing functionality.
            ExcelAllowExternalData = $true #Enables the refresh of supported external data in Excel Web App workbooks where workbooks contain connections to external data. The default is True.
            ExcelConnectionLifetime = 1800 #Specifies the duration, in seconds, of external data connections for Excel Web App. The default is 1800 seconds.
            ExcelExternalDataCacheLifetime = 300 #Specifes the duration, in seconds, of the external data cache lifetime in Excel Web App. The default is 300 seconds.
            ExcelPrivateBytesMax = -1 #Specifies the maximum private bytes, in megabytes, used by Excel Web App. When set to -1, the maximum private bytes use 50 percent of physical memory on the computer.
            ExcelRequestDurationMax = 600 #Specifies the maximum duration, in seconds, for a single request in a session. After this time elapses, the request times out.
            ExcelSessionTimeout = 1200 #Specifies the time, in seconds, that a session remains active in Excel Web App when there is no user activity.
            ExcelUdfsAllowed = $false #Activates user-defined functions for use with Web Excel.
            ExcelWarnOnDataRefresh = $true #Turns off or on the warning dialog displayed when data refreshes in Excel Web App.
            ExcelWorkbookSizeMax = 10240 #Specifies the maximum size, in megabytes, of a workbook that can be loaded.
            ExcelMemoryCacheThreshold = 50 #The percentage of the Maximum Private Bytes that can be allocated to inactive objects. When the memory cache threshold is exceeded, cached objects that are not currently in use are released.
            ExcelUnusedObjectAgeMax = 5 #The maximum time (in minutes) that inactive objects remain in the memory cache. Inactive objects are objects that are not used in a session.
            ExcelCachingUnusedFiles = $false #Enable caching of files that are no longer in use by Web Excel sessions.
            ExcelAbortOnRefreshOnOpenFail = $false #Specifies that the loading of a Web Excel file automatically fails if an automatic data refresh operation fails when the file is opened.
            ExcelAutomaticVolatileFunctionCacheLifetime = 30 #Specifies the maximum time, in seconds, that a computed value for a volatile function is cached for automatic recalculations.
            ExcelConcurrentDataRequestsPerSessionMax = 50 #Specifies the maximum number of concurrent external data requests allowed in each session. If a session must issue more than this number of requests, additional requests must be queued. The scope of this setting is the logical server.
            ExcelDefaultWorkbookCalcMode = "Auto" #Specifies the calculation mode of workbooks. Settings other than File override the workbook settings. (File, Manual, Auto, and AutoDataTables)
            ExcelRestExternalDataEnabled = $false #Specifies whether requests from the Representational State Transfer (REST) Application Programming Interface (API) are permitted to refresh external data connections.
            ExcelChartAndImageSizeMax = 5 #Specifies the maximum size, in megabytes, of a chart or image that can be opened.
            ExternalURL = "https://oos.weaverind.com" #Specifies the URL root that clients use to access the Office Web Apps Server farm from the Internet. In the case of a load-balanced, multiserver Office Web Apps Server farm, the external URL is bound to the IP address of the external-facing load balancer.
            FarmOU = $null #Specifies the name of the Active Directory organizational unit (OU) that servers must be a member of to join the Office Web Apps Server farm. Use this parameter to prevent unauthorized servers (that is, servers that are not in the OU) from joining an Office Web Apps Server farm.
            InternalURL = "http://oos.weaver.ad" #Specifies the URL root that clients use to access the Office Web Apps Server farm from the intranet.
            LogLocation = "C:\Logs" #Specifies the location on the local computer where activity logs are stored.
            LogRetentionInDays = 30 #Specifies the number of days that log entries are stored. Log entries older than the configured date are trimmed.
            LogVerbosity = "High" #Specifies how much information is stored in the trace log files. (VerboseEX,Verbose,Medium,High,Monitorable,Unexpected,None)
            MaxMemoryCacheSizeInMB = 1024 #Specifies, in megabytes, the maximum amount of memory that the rendering cache can use.
            MaxTranslationCharacterCount = 50000 #Specifies the maximum amount of characters a document can have in order to be translated.
            OpenFromUncEnabled = $false #Turns on or off the ability to use Online Viewers to view Office files from a UNC path.
            OpenFromUrlEnabled = $true #Turns on or off the ability to use Online Viewers to view Office files from a URL or UNC path.
            OpenFromUrlThrottlingEnabled = $null #Throttles the number of open from URL requests from any given server in a time period. The default throttling values, which are not configurable, make sure that an Office Web Apps Server farm will not overwhelm a single server with requests for content to be viewed in the Online Viewers.
            Proxy = $null #Specifies the URL of the proxy server that is configured to allow HTTP requests to external sites. Typically configured in conjunction with the ClipartEnabled and TranslationEnabled parameters.
            RecycleActiveProcessCount = 10 #Specifies the number of files that a single Word or PowerPoint process can render before the process is recycled. (1 - 1000 Default 5)
            RenderingLocalCacheLocation = $null #Specifies the location of the temporary cache for use by the Word and PowerPoint Viewing Services. (Default is %programdata%\Microsoft\OfficeWebApps\Working\waccache)
            SSLOffloaded = $false #Indicates to the servers in the Office Web Apps Server farm that SSL is offloaded to the load balancer. When SSLOffloaded is enabled, web applications are bound to port 80 (HTTP) on the local server. However, HTML that references other resources, such as CSS or images, uses HTTPS URLs for those references.
            TranslationEnabled = $true #Enables support for automatic document translation using Microsoft Translator, an online service that translates text between languages. The translated file is shown in the Word Web App. Because Microsoft Translator is an online service, you must enable server-to-web communication directly or by using a proxy that you specify by using the Proxy parameter.
            TranslationServiceAddress = $null #Specifies the URL of the translation server that translation requests are sent to. The default is the Microsoft Translator online service. Typically you will not use this parameter unless you must change translation services.
            TranslationServiceAppId = $null #Specifies the application ID for the translation service. The default is the public application ID for Office Web Apps. Typically you will not use this parameter unless you have negotiated with Microsoft Translator for additional services and they have provided you with a private application ID.
            AllowOutboundHttp = $false
            ExcelUseEffectiveUserName = $true
            S2SCertificateName = $null
            RemovePersonalInformationFromLogs = $false
            PicturePasteDisabled = $false
        }
        SharePoint = @{
            Version                     = 2016
            Installation = @{
                InstallKey              = "TY6N4-K9WD3-JD2J2-VYKTJ-GVJ2J"
                BinaryDir               = "\\DSC01\DSCShare\SP2016Bits"
                PrereqInstallerPath     = "\\DSC01\DSCShare\SP2016bits\prerequisiteinstallerfiles"
                PrereqInstallMode       = $true
            }
            Farm = @{
                ConfigurationDatabase   = "SP_Config"
                AdminContentDatabase    = "SP_Admin_Content"
                CentralAdminPort        = 5000
                CentralAdminAuth        = "NTLM"       #Valid values are "NTLM" or "Kerberos"
               # CentralAdminUrl         = ""           # Optional vanity url so you can use SSL with CA, leave commented out unless you want to use
                DeveloperDashBoard      = "Off"        #Valid values are "Off" or "On"
                FarmAdmins              = @("WEAVER\administrator","WEAVER\christwe")            #Do not add farm account or setup account, script will take care of that in background
                ExcludeFromFarmAdmins   = "" #Accounts or groups you want to ensure are not included in Farm Admin group (DO NOT PLACE SERVICE ACCOUNTS HERE)
                SiteQuotaTemplates = @(
                    @{
                        QuotaName = "Default"
                        QuotaStorageMaxInMB = 10240
                        QuotaStorageWarningInMB = 7168
                        QuotaMaximumUsagePointsSolutions = 300
                        QuotaWarningUsagePointsSolutions = 250
                    },
                    @{
                        QuotaName = "Large"
                        QuotaStorageMaxInMB = 102400
                        QuotaStorageWarningInMB = 71680
                        QuotaMaximumUsagePointsSolutions = 300
                        QuotaWarningUsagePointsSolutions = 250
                    }
                )          
            }
         
            # You can have only one of each kind except for 'ConnectionAccount' which you can have multiple leave @() in place even if you only have one account
            ServiceAccounts = @{
                SetupAccount            = "WEAVER\sp2016setup"
                FarmAccount             = "WEAVER\sp2016farm"
                WebAppPoolAccount       = "WEAVER\sp2016webpool"
                ServicesAppPoolAccount  = "WEAVER\sp2016apppool"
                ContentAccessAccount    = "WEAVER\sp2016crawl"
               # ConnectionAccount       = @("WEAVER\spconnacct")
                ManagedAccountPasswordResetSettings = @{  
                        AdministratorMailAddress      = "sharepointadmin@weaver.ad"
                        SendmessageDaysBeforeExpiry   = "14"
                        PasswordChangeTimeoutinSec    = "60"
                        PasswordChangeNumberOfRetries = "3"
                }
            }
            DiagnosticLogs = @{
                Path                                        = "C:\ULSLogs"
                MaxSizeGB                                   = 1
                DaysToKeep                                  = 1
                AppAnalyticsAutomaticUploadEnabled          = $false
                CustomerExperienceImprovementProgramEnabled = $true
                DownloadErrorReportingUpdatesEnabled        = $false
                ErrorReportingAutomaticUploadEnabled        = $false
                ErrorReportingEnabled                       = $false
                EventLogFloodProtectionEnabled              = $true
                EventLogFloodProtectionNotifyInterval       = 5
                EventLogFloodProtectionQuietPeriod          = 2
                EventLogFloodProtectionThreshold            = 5
                EventLogFloodProtectionTriggerPeriod        = 2
                LogCutInterval                              = 15
                LogMaxDiskSpaceUsageEnabled                 = $true
                ScriptErrorReportingDelay                   = 30
                ScriptErrorReportingEnabled                 = $true
                ScriptErrorReportingRequireAuth             = $true
            }
            UsageLogs = @{
                DatabaseName            = "SP_Usage"
                Path                    = "C:\UsageLogs"
            }
            Services = @{
                ApplicationPoolName     = "SharePoint Service Applications"
            }
            StateService = @{
                Name                    = "State Service Application"
                DatabaseName            = "SP_State"
            }
            WebApplications = @(
                  @{
                    UseClassic          = $true  #If Auth will be kerberos this must be $true
                    Auth_DefaultZone    = "Kerberos"     #NTLM or Kerberos
                    Name                = "SharePoint"
                    DatabaseName        = "SP_Content_DB001"
                    Url                 = "https://sp.weaver.ad"
                    Anonymous           = $false
                    BindingHostHeader   = "sp.weaver.ad"
                    WebPort             = 443
                    AppPool             = "Web App Pool"
                    AppPoolAccount      = "WEAVER\sp2016apppool"
                    SuperUser           = "WEAVER\sp2016superuser"
                    SuperReader         = "WEAVER\sp2016superreader"
                    UseHostNamedSiteCollections = $false
                    BindingIP = ""
                    BlockedFileTypes = @()
                   # WebPath = "$env:SystemDrive\inetpub\wwwroot\SharePoint"
                    SSLCertificate = "\\DSC01\DSCShare\Certificates\spweaver.pfx"    #MUST BE PFX, File to import into certificae repository on server NOTE: If multiple SSL web apps you need a Wildcard cert, Leave blank if not using SSL
                    PFXPassword = "P@ssword1"
                    SSLCertificateThumbPrint = "‎8bf82c0f2d8bacae6a02a77cb032fc79df5effcf"
                    MaximumUploadSize   = 1024
                    TimeZone = 11 #https://msdn.microsoft.com/en-us/library/office/microsoft.sharepoint.spregionalsettings.timezones.aspx 
                    Alerts = $true
                    AlertsLimit = 5000
                    RSS = $true
                    BlogAPI = $true
                    BlogAPIAuthenticated = $true
                    BrowserFileHandling = "Permissive" #Strict, Permissive
                    SecurityValidation = $true
                    SecurityValidationExpires = $true
                    SecurityValidationTimeOutMinutes = 5
                    RecycleBinEnabled = $true
                    RecycleBinCleanupEnabled = $true
                    RecycleBinRetentionPeriod = 30 #Days
                    SecondStageRecycleBinQuota = 20 #Percentage
                    CustomerExperienceProgram = $true
                    AllowOnlineWebPartCatalog = $true
                    SelfServiceSiteCreationEnabled = $false
                    PresenceEnabled = $true
                    DefaultQuotaTemplate = "Default" # See values from SharePoint.Farm.SiteQuotaTemplate
                    ManagedPaths = @(
                        @{
                            Path        = "sites"
                            Explicit    = $false
                        },
                        @{
                            Path        = "search"
                            Explicit    = $true
                        }
                    )
                  },
                  @{
                    UseClassic          = $false
                    Auth_DefaultZone    = "NTLM"     #NTLM or Kerberos
                    Name                = "MySites"
                    DatabaseName        = "MySites_Content_DB001"
                    Url                 = "http://mysites.weaver.ad"
                    Anonymous           = $false
                    BindingHostHeader   = "mysites.weaver.ad"
                    WebPort             = 80
                    AppPool             = "Web App Pool"
                    AppPoolAccount      = "WEAVER\sp2016apppool"
                    SuperUser           = "WEAVER\sp2016superuser"
                    SuperReader         = "WEAVER\sp2016superreader"
                    UseHostNamedSiteCollections = $false
                    BindingIP = ""
                    BlockedFileTypes = @()
                  #  WebPath = "%SystemDrive%\inetpub\wwwroot\MySites"
                    SSLCertificate = ""
                    SSLCertificateThumbPrint = ""
                    MaximumUploadSize   = 1024
                    TimeZone = 11 #https://msdn.microsoft.com/en-us/library/office/microsoft.sharepoint.spregionalsettings.timezones.aspx 
                    Alerts = $true
                    AlertsLimit = 5000
                    RSS = $true
                    BlogAPI = $true
                    BlogAPIAuthenticated = $true
                    BrowserFileHandling = "Strict" #Strict, Permissive
                    SecurityValidation = $true
                    SecurityValidationExpires = $true
                    SecurityValidationTimeOutMinutes = 5
                    RecycleBinEnabled = $true
                    RecycleBinCleanupEnabled = $true
                    RecycleBinRetentionPeriod = 30 #Days
                    SecondStageRecycleBinQuota = 20 #Percentage
                    CustomerExperienceProgram = $true
                    AllowOnlineWebPartCatalog = $true
                    SelfServiceSiteCreationEnabled = $true
                    PresenceEnabled = $true
                    DefaultQuotaTemplate = "Default"
                    ManagedPaths = @(
                        @{
                            Path        = "my"
                            Explicit    = $true
                        }
                    )
                    SiteCollections = @(
                        @{
                            Url         = "http://mysites.weaver.ad/"
                            Owner       = "Weaver\sp2016farm"
                            Name        = "My Site Host"
                            Template    = "SPSMSITEHOST#0"
                            Database    = "Mysites_Content_DB001"
                            HostNamedSiteCollection = $false
                            CompatibilityLevel = $null #When not specified, the CompatibilityLevel will default to the highest possible version for the web application
                            Description = "My Site Host Site Collection"
                            Language = 1033
                            OwnerEmail = ""
                            QuotaTemplate = "Default"
                            SecondaryOwnerAlias = "weaver\administrator"
                            SecondaryEmail = ""
                            CreateDefaultGroups = $true
                        }
                    )
                  },
                @{
                    UseClassic          = $false
                    Auth_DefaultZone    = "NTLM"     #NTLM or Kerberos
                    Name                = "ECM"
                    DatabaseName        = "ECM_Content_DB001"
                    Url                 = "http://ecm.weaver.ad"
                    Anonymous           = $true
                    BindingHostHeader   = "ecm.weaver.ad"
                    WebPort             = 80
                    AppPool             = "Web App Pool"
                    AppPoolAccount      = "WEAVER\sp2016apppool"
                    SuperUser           = "WEAVER\sp2016superuser"
                    SuperReader         = "WEAVER\sp2016superreader"
                    UseHostNamedSiteCollections = $false
                    BindingIP = ""
                    BlockedFileTypes = @()
                 #   WebPath = "%SystemDrive%\inetpub\wwwroot\ECM"
                    SSLCertificate = ""
                    SSLCertificateThumbPrint = ""
                    MaximumUploadSize   = 1024
                    TimeZone = 11 #https://msdn.microsoft.com/en-us/library/office/microsoft.sharepoint.spregionalsettings.timezones.aspx 
                    Alerts = $true
                    AlertsLimit = 5000
                    RSS = $true
                    BlogAPI = $true
                    BlogAPIAuthenticated = $true
                    BrowserFileHandling = "Strict" #Strict, Permissive
                    SecurityValidation = $true
                    SecurityValidationExpires = $true
                    SecurityValidationTimeOutMinutes = 5
                    RecycleBinEnabled = $true
                    RecycleBinCleanupEnabled = $true
                    RecycleBinRetentionPeriod = 30 #Days
                    SecondStageRecycleBinQuota = 20 #Percentage
                    CustomerExperienceProgram = $true
                    AllowOnlineWebPartCatalog = $true
                    SelfServiceSiteCreationEnabled = $false
                    PresenceEnabled = $true
                    DefaultQuotaTemplate = "Default"
                    ManagedPaths = @(
                        @{
                            Path        = "projects"
                            Explicit    = $false
                        }
                    )
                },
               @{
                    UseClassic          = $false
                    Auth_DefaultZone    = "NTLM"     #NTLM or Kerberos
                    Name                = "TeamSites"
                    DatabaseName        = "TeamSites_Content_DB001"
                    Url                 = "http://TeamSites.weaver.ad"
                    Anonymous           = $false
                    BindingHostHeader   = ""
                    WebPort             = 80
                    AppPool             = "Web App Pool"
                    AppPoolAccount      = "WEAVER\sp2016apppool"
                    SuperUser           = "WEAVER\sp2016superuser"
                    SuperReader         = "WEAVER\sp2016superreader"
                    UseHostNamedSiteCollections = $true
                    BindingIP = ""
                    BlockedFileTypes = @()
                  #  WebPath = "%SystemDrive%\inetpub\wwwroot\TeamSites"
                    SSLCertificate = ""
                    SSLCertificateThumbPrint = ""
                    MaximumUploadSize   = 1024
                    TimeZone = 2 #https://msdn.microsoft.com/en-us/library/office/microsoft.sharepoint.spregionalsettings.timezones.aspx 
                    Alerts = $true
                    AlertsLimit = 5000
                    RSS = $true
                    BlogAPI = $true
                    BlogAPIAuthenticated = $true
                    BrowserFileHandling = "Permissive" #Strict, Permissive
                    SecurityValidation = $false
                    SecurityValidationExpires = $true
                    SecurityValidationTimeOutMinutes = 5
                    RecycleBinEnabled = $true
                    RecycleBinCleanupEnabled = $true
                    RecycleBinRetentionPeriod = 60 #Days
                    SecondStageRecycleBinQuota = 20 #Percentage
                    CustomerExperienceProgram = $false
                    AllowOnlineWebPartCatalog = $true
                    SelfServiceSiteCreationEnabled = $false
                    PresenceEnabled = $true
                    DefaultQuotaTemplate = "Default"
                    SiteCollections = @(
                        @{
                            Url         = @("http://IT.weaver.ad/","http://InfoTech.weaver.local","http://IT.weaver.int")
                            Owner       = "Weaver\sp2016farm"
                            Name        = "IT Team Site"
                            Template    = "STS#0"
                            Database    = "TeamSites_Content_DB001"
                            HostNamedSiteCollection = $true
                            CompatibilityLevel = $null #When not specified, the CompatibilityLevel will default to the highest possible version for the web application
                            Description = "Site Collection to hold all IT data and process documentation"
                            Language = 1033
                            OwnerEmail = ""
                            QuotaTemplate = "Large"
                            SecondaryOwnerAlias = "weaver\administrator"
                            SecondaryEmail = ""
                            CreateDefaultGroups = $true
                        },
                        @{
                            Url         = "http://LCA.weaver.ad/"
                            Owner       = "weaver\administrator"
                            Name        = "LCA Team Site"
                            Template    = "STS#0"
                            Database    = "TeamSites_Content_DB001"
                            HostNamedSiteCollection = $true
                            CompatibilityLevel = $null #When not specified, the CompatibilityLevel will default to the highest possible version for the web application
                            Description = "Site Collection to hold all Legal data and process documentation"
                            Language = 1033
                            OwnerEmail = ""
                            QuotaTemplate = "Default"
                            SecondaryOwnerAlias = "weaver\sp2016setup"
                            SecondaryEmail = ""
                            CreateDefaultGroups = $true
                        }
                    )
                   }
            )
            UserProfileService = @{
                Name                    = "User Profile Service Application"
                ProxyName               = "User Profile Service Application Proxy"
                NetbiosEnable           = $false
                MySiteUrl               = "http://mysites.weaver.ad/"
                ProfileDB               = "SP_UPA_Profile"
                SocialDB                = "SP_UPA_Social"
                SyncDB                  = "SP_UPA_Sync"
                UseADImport             = $true
                UserProfileSyncConnection = @(
                    @{
                        Forest = "weaver.ad"
                        Domain = "weaver"  #only for SP2016
                        Name = "Weaver Domain"
                        ConnectionUsername = "WEAVER\SPConnAcct"
                        Server = "" #Best to leave blank but you can add a server if that is better for your architecture
                        UseSSL = $false
                        IncludedOUs = @("OU=Users,OU=Enterprise,DC=weaver,DC=ad")
                        ExcludedOUs = @("OU=Service Accounts,OU=Enterprise,DC=weaver,DC=ad") #Not supported in SP2016
                        Force = $false
                    }
                )
            }
            SecureStoreService = @{
                Name                    = "Secure Store Service Application"
                DatabaseName            = "SP_SecureStore"
                AuditLogMaxSize         = 30
                AuditingEnabled         = $true
            }
            ManagedMetadataService = @{
                Name                    = "Managed Metadata Service Application"
                DatabaseName            = "SP_MMS"
            }
            BCSService = @{
                Name                    ="BCS Service Application" 
                DatabaseName            = "SP_BCS"
            }
            Search = @(
            @{
                Name                    = "Search Service Application"
                DatabaseName            = "SP_Search"
                CloudSSA                = $false
                SearchTopology = @{
                    Admin               = @("SP2016APP01")
                    Crawler             = @("SP2016APP01")
                    ContentProcesing    = @("SP2016APP01";"SP2016APP02")
                    AnalyticsProcesing = @("SP2016APP01")
                    QueryProcesing      = @("SP2016APP01")
                    IndexPartition0      = @("SP2016APP01")
                    IndexPartition0Folder = "C:\searchindex\0"
                    IndexPartitions = @(
                        @{
                            Index = 1       #Starting from 1 increment for each additional partition
                            Servers = @("SP2016APP02")
                            IndexPartitionFolder = "C:\SearchIndex\1"
                        }
                    )
                }
            <#    SearchContentSource = @(       #Can use this to help with schedules https://www.powershellgallery.com/packages/SharePointDSC/1.0.0.0/Content/DSCResources%5CMSFT_SPSearchContentSource%5CMSFT_SPSearchContentSource.schema.mof
                    @{                         # Currently only support ContentSourceType 'SharePoint"
                        Name                 = "Collab and ECM Content"
                        ServiceAppName       = "Search Service Application"
                        ContentSourceType    = "SharePoint"           #Possible values SharePoint, Website, or FileShare
                        Addresses            = @("http://sp.weaver.ad","http://ecm.weaver.ad")
                        CrawlSetting         = "CrawlEverything"      #Possible values CrawlEverything, CrawlFirstOnly, Custom
                        ContinuousCrawl      = $true
                        IncrementalSchedule  = @{        #Set to $null if you don't want to set a schedule
                            ScheduleType = "Daily"       #Can be set to None, Daily, Weekly, Monthly
                            StartHour = "0"
                            StartMinute = "0"
                            CrawlScheduleRepeatDuration = "1440"
                            CrawlScheduleRepeatInterval = "5"
                        }
                        FullSchedule         = @{
                            ScheduleType = "Weekly"
                            CrawlScheduleDaysOfWeek = @("Everyday")     #Everyday is also acceptable value
                            StartHour = "3"
                            StartMinute = "0"
                        }
                        Priority             = "Normal"               #Possible values Normal or High
                    },
                    @{
                        Name                 = "Social Content"
                        ServiceAppName       = "Search Service Application"
                        ContentSourceType    = "SharePoint"
                        Addresses            = @("http://mysites.weaver.ad")
                        CrawlSetting         = "CrawlEverything"
                        ContinuousCrawl      = $true
                        IncrementalSchedule  =  $null
                        FullSchedule         = @{
                            ScheduleType = "Monthly"
                            CrawlScheduleDaysofMonth = 15
                            CrawlScheduleMonthsofYear = @("AllMonths")
                            StartHour = "3"
                            StartMinute = "0"
                        }
                        Priority             = "Normal"
                    }
                )#>
            }
            )
            OutgoingEmail = @(            #Note if you want to set farm wide then WebAppUrl needs to be set to CA, if you want you can also set to WebApp or both
                @{
                    WebAppUrl               = "http://sp2016app01:5001"
                    SMTPServer              = "internalmail.weaver.ad"
                    FromAddress             = "sharepointadmin@weaver.ad"
                    ReplyToAddress          = "sharepointadmin@weaver.ad"
                    CharacterSet            = "65001"
                },
                @{
                    WebAppUrl               = "https://sp.weaver.ad"
                    SMTPServer              = "internalmail.weaver.ad"
                    FromAddress             = "sharepointadmin@weaver.ad"
                    ReplyToAddress          = "sharepointadmin@weaver.ad"
                    CharacterSet            = "65001"
                }
            )
            InboundEmail = @{
                Enable = $true
                EmailDomain = "sharepoint.weaver.ad"
            }
            DCache = @{
                CacheSizeInMB           = 2048
            }
            AppManagementService = @{
                Name                    = "Application Management Service Application"
                DatabaseName            = "SP_AppManagement"
            }
            SubscriptionSettingsService = @{
                Name                    = "Subscription Settings Service Application"
                DatabaseName            = "SP_SubscriptionSettings"
            }
            VisioService = @{
                Name                    = "Visio Service Application"
            }
            WordAutomationService = @{
                Name                    = "Word Automation Service Application"
                DatabaseName            = "SP_WordAutomation"
            }
        }
     }
 }