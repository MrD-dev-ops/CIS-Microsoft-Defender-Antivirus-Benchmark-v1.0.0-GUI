#Run this script with elevated privileges (Run as Administrator) to ensure it can access and modify the necessary registry keys for compliance checks and remediation.
#& { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force }


#Requires -RunAsAdministrator
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:BenchmarkTitle = "CIS Microsoft Defender Antivirus Benchmark for Windows 11"
$script:BenchmarkVersion = "v1.0.0"
$script:BenchmarkReleaseDate = "02/20/2026"
$script:isUpdatingGrid = $false

# Ensure PolicyFileEditor module is available for local GPO .pol backing store persistence
if (-not (Get-Module -ListAvailable -Name PolicyFileEditor)) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Install-Module -Name PolicyFileEditor -Force -Scope AllUsers -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not install PolicyFileEditor module automatically: $_"
    }
}
Import-Module PolicyFileEditor -ErrorAction SilentlyContinue

$script:Checks = @(
    @{
        Id            = '1.4.1'
        Title         = "Ensure 'Enable EDR in block mode' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features'
        PropertyName  = 'PassiveRemediation'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.5.1'
        Title         = "Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        PropertyName  = 'LocalSettingOverrideSpynetReporting'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.5.2'
        Title         = "Ensure 'Configure the 'Block at First Sight' feature' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        PropertyName  = 'DisableBlockAtFirstSeen'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.5.3'
        Title         = "Ensure 'Join Microsoft MAPS' is set to 'Enabled: Advanced'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        PropertyName  = 'SpynetReporting'
        ExpectedValue = 2
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.5.4'
        Title         = "Ensure 'Send file samples when further analysis is required' is set to 'Enabled: Send safe samples automatically' or higher."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'
        PropertyName  = 'SubmitSamplesConsent'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.1'
        Title         = "Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
        PropertyName  = 'ExploitGuard_ASR_Rules'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.2'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to '56a863a9-875e-4185-98a7-b882c64b5ce5:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = '56a863a9-875e-4185-98a7-b882c64b5ce5'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.3'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.4'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to 'd4f940ab-401b-4efc-aadc-ad5f3c50688a:2' or higher."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a'
        ExpectedValue = 2
        Operator      = 'ge'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.5'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.6'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.7'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to '01443614-cd74-433a-b99e-2ecdc07bfc25:2' or higher."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = '01443614-cd74-433a-b99e-2ecdc07bfc25'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.8'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to '5beb7efe-fd9a-4556-801d-275e5ffc04cc:2' or higher."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.9'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to 'd3e037e1-3eb8-44c8-a917-57927947596d:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = 'd3e037e1-3eb8-44c8-a917-57927947596d'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.10'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to '3b576869-a4ec-4529-8536-b80a7769e899:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = '3b576869-a4ec-4529-8536-b80a7769e899'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.11'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.12'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to '26190899-1602-49e8-8b27-eb1d0a1ce869:1' or higher."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = '26190899-1602-49e8-8b27-eb1d0a1ce869'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.13'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to 'e6db77e5-3df2-4cf1-b95a-636979351e5b:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.14'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to '33ddedf1-c6e0-47cb-833e-de6133960387:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = '33ddedf1-c6e0-47cb-833e-de6133960387'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.15'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.16'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b:1'."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.1.17'
        Title         = "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is set to 'c1db55ab-c21a-4637-bb3f-a12568109d35:1' or higher."
        Path          = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
        PropertyName  = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.6.3.1'
        Title         = "Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
        PropertyName  = 'EnableNetworkProtection'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.7.1'
        Title         = "Ensure 'Enable file hash computation feature' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        PropertyName  = 'EnableFileHashComputation'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.7.2'
        Title         = "Ensure 'Select cloud protection level' is set to 'Enabled: Moderate blocking level' or higher."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'
        PropertyName  = 'MpCloudBlockLevel'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.8.1'
        Title         = "Ensure 'Convert warn verdict to block' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS'
        PropertyName  = 'EnableConvertWarnToBlock'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.10.1'
        Title         = "Ensure 'Configure monitoring for incoming and outgoing file and program activity' is set to 'Enabled: bi-directional (full on access)'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        PropertyName  = 'RealtimeScanDirection'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.10.2'
        Title         = "Ensure 'Configure real-time protection and Security Intelligence Updates during OOBE' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        PropertyName  = 'OobeEnableRtpAndSigUpdate'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.10.3'
        Title         = "Ensure 'Monitor file and program activity on your computer' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        PropertyName  = 'DisableOnAccessProtection'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.10.4'
        Title         = "Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
        PropertyName  = 'DisableIOAVProtection'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.10.5'
        Title         = "Ensure 'Turn off real-time protection' is set to 'Disabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection'
        PropertyName  = 'DisableRealtimeMonitoring'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.10.6'
        Title         = "Ensure 'Turn on behavior monitoring' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection'
        PropertyName  = 'DisableBehaviorMonitoring'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.10.7'
        Title         = "Ensure 'Turn on process scanning whenever real-time protection is enabled' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection'
        PropertyName  = 'DisableScanOnRealtimeEnable'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.10.8'
        Title         = "Ensure 'Turn on script scanning' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection'
        PropertyName  = 'DisableScriptScanning'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.11.1.1.1'
        Title         = "Ensure 'Configure Brute-Force Protection aggressiveness' is set to 'Enabled: Medium' or higher."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection'
        PropertyName  = 'BruteForceProtectionAggressiveness'
        ExpectedValue = 1
        Operator      = 'ge'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.11.1.1.2'
        Title         = "Ensure 'Configure Remote Encryption Protection Mode' is set to 'Enabled: Audit' or higher."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection'
        PropertyName  = 'BruteForceProtectionConfiguredState'
        ExpectedValue = 2
        Operator      = 'ge'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.11.1.2.1'
        Title         = "Ensure 'Configure how aggressively Remote Encryption Protection blocks threats' is set to 'Enabled: Medium' or higher."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection'
        PropertyName  = 'RemoteEncryptionProtectionAggressiveness'
        ExpectedValue = 1
        Operator      = 'ge'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.11.1.2.2'
        Title         = "Ensure 'Configure Remote Encryption Protection Mode' is set to 'Enabled: Audit' or higher."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection'
        PropertyName  = 'RemoteEncryptionProtectionConfiguredState'
        ExpectedValue = 2
        Operator      = 'ge'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.12.1'
        Title         = "Ensure 'Configure Watson events' is set to 'Disabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
        PropertyName  = 'DisableGenericReReports'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.12.2'
        Title         = "Ensure 'Configure whether to report Dynamic Signature dropped events' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'
        PropertyName  = 'EnableDynamicSignatureDroppedEventReporting'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.1'
        Title         = "Ensure 'Check for the latest virus and spyware security intelligence before running a scheduled scan' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'CheckForSignaturesBeforeRunningScan'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.2'
        Title         = "Ensure 'Scan archive files' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'DisableArchiveScanning'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.3'
        Title         = "Ensure 'Scan excluded files and directories during quick scans' is set to 'Enabled: 1'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'QuickScanIncludeExclusions'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.4'
        Title         = "Ensure 'Scan packed executables' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'DisablePackedExeScanning'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.5'
        Title         = "Ensure 'Scan removable drives' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'DisableRemovableDriveScanning'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.6'
        Title         = "Ensure 'Turn on e-mail scanning' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'DisableEmailScanning'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.7'
        Title         = "Ensure 'Specify the scan type to use for a scheduled scan' is set to 'Enabled: Quick Scan (default)' or higher."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'ScanParameters'
        ExpectedValue = 1
        Operator      = 'ge'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.8'
        Title         = "Ensure 'Specify the time for a daily quick scan' is set to 'Enabled: 1' or higher."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'ScheduleQuickScanTime'
        ExpectedValue = 1
        Operator      = 'ge'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.9'
        Title         = "Ensure 'Specify the time of day to run a scheduled scan' is set to 'Enabled: 1' or higher."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'ScheduleTime'
        ExpectedValue = 1
        Operator      = 'ge'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.10'
        Title         = "Ensure 'Trigger a quick scan after X days without any scans' is set to 'Enabled: 7'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'DaysUntilAggressiveCatchupQuickScan'
        ExpectedValue = 7
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.13.11'
        Title         = "Ensure 'Turn on e-mail scanning' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'
        PropertyName  = 'DisableEmailScanning'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.14.1'
        Title         = "Ensure 'Specify the interval to check for security intelligence updates' is set to 'Enabled: 4' or fewer, but not '0'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates'
        PropertyName  = 'SignatureUpdateInterval'
        ExpectedValue = 4
        Operator      = 'le'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.15.1'
        Title         = "Ensure 'Specify threat alert levels at which default action should not be taken when detected' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats'
        PropertyName  = 'Threats_ThreatSeverityDefaultAction'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.15.2'
        Title         = "Ensure 'Specify threat alert levels at which default action should not be taken when detected' is set to 'Enabled: Medium: 2 or 3'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
        PropertyName  = '2'
        ExpectedValue = '2'
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.15.3'
        Title         = "Ensure 'Specify threat alert levels at which default action should not be taken when detected' is set to 'Enabled: High: 2 or 3'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
        PropertyName  = '4'
        ExpectedValue = '2'
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.15.4'
        Title         = "Ensure 'Specify threat alert levels at which default action should not be taken when detected' is set to 'Enabled: Severe: 2 or 3'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
        PropertyName  = '5'
        ExpectedValue = '2'
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.16'
        Title         = "Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        PropertyName  = 'PUAProtection'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.17'
        Title         = "Ensure 'Control whether exclusions are visible to local users' is set to 'Enabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        PropertyName  = 'HideExclusionsFromLocalUsers'
        ExpectedValue = 1
        Operator      = 'eq'
        Version       = '1.0.0'
    },
    @{
        Id            = '1.18'
        Title         = "Ensure 'Turn off routine remediation' is set to 'Disabled'."
        Path          = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        PropertyName  = 'DisableRoutinelyTakingAction'
        ExpectedValue = 0
        Operator      = 'eq'
        Version       = '1.0.0'
    }
)

function Get-ComplianceResult {
    param($Check)
    $actualValue = $null
    try {
        $actualValue = Get-ItemPropertyValue -Path $Check.Path -Name $Check.PropertyName -ErrorAction Stop
    }
    catch {
        $actualValue = $null
    }

    $compliant = $false
    if ($null -ne $actualValue) {
        if ($Check.Id -in @('1.15.2', '1.15.3', '1.15.4')) {
            $compliant = ("$actualValue" -eq "2" -or "$actualValue" -eq "3")
        }
        elseif ($Check.Operator -eq 'ge') {
            $compliant = ($actualValue -ge $Check.ExpectedValue)
        }
        elseif ($Check.Operator -eq 'le') {
            $compliant = ($actualValue -gt 0 -and $actualValue -le $Check.ExpectedValue)
        }
        else {
            $compliant = ("$actualValue" -eq "$($Check.ExpectedValue)")
        }
    }
    return @{
        Id             = $Check.Id
        Title          = $Check.Title
        ExpectedValue  = $Check.ExpectedValue
        ActualValue    = $actualValue
        Compliant      = $compliant
        Version        = $Check.Version
    }
}

$script:compliantCount = 0
$script:nonCompliantCount = 0

function Invoke-ComplianceRun {
    $script:isUpdatingGrid = $true
    $script:compliantCount = 0
    $script:nonCompliantCount = 0
    $dataGridView.Rows.Clear()
    
    foreach ($check in $script:Checks) {
        $result = Get-ComplianceResult -Check $check
        if ($result.Compliant) {
            $script:compliantCount = $script:compliantCount + 1
            $statusText = 'Compliant'
            $statusBg = [System.Drawing.Color]::FromArgb(212, 237, 218)
            $statusFg = [System.Drawing.Color]::FromArgb(21, 87, 36)
        }
        else {
            $script:nonCompliantCount = $script:nonCompliantCount + 1
            $statusText = 'Non-Compliant'
            $statusBg = [System.Drawing.Color]::FromArgb(248, 215, 218)
            $statusFg = [System.Drawing.Color]::FromArgb(114, 28, 36)
        }
        
        $rowIndex = $dataGridView.Rows.Add($result.Compliant, $statusText, $result.Id, $result.Version, $result.Title, $result.ExpectedValue, $result.ActualValue)
        $row = $dataGridView.Rows[$rowIndex]
        
        $row.Cells[1].Style.BackColor = $statusBg
        $row.Cells[1].Style.ForeColor = $statusFg
    }
    $lblSummary.Text = "Compliant: $($script:compliantCount) of $($script:Checks.Count) | Non-Compliant: $($script:nonCompliantCount) of $($script:Checks.Count)"
    $script:isUpdatingGrid = $false
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "$script:BenchmarkTitle ($script:BenchmarkVersion) - Compliance & Remediation"
$form.Size = New-Object System.Drawing.Size -ArgumentList 1150, 750
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.MinimumSize = New-Object System.Drawing.Size -ArgumentList 1150, 750

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "$script:BenchmarkTitle - $script:BenchmarkVersion (Released $script:BenchmarkReleaseDate)"
$lblTitle.Location = New-Object System.Drawing.Point -ArgumentList 20, 20
$lblTitle.Size = New-Object System.Drawing.Size -ArgumentList 1100, 30
$lblTitle.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 12, [System.Drawing.FontStyle]::Bold)
$lblTitle.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$form.Controls.Add($lblTitle)

$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = 'Run Compliance Check'
$btnRun.Location = New-Object System.Drawing.Point -ArgumentList 20, 58
$btnRun.Size = New-Object System.Drawing.Size -ArgumentList 160, 34
$btnRun.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$form.Controls.Add($btnRun)

$btnEnableAll = New-Object System.Windows.Forms.Button
$btnEnableAll.Text = 'Enable All'
$btnEnableAll.Location = New-Object System.Drawing.Point -ArgumentList 190, 58
$btnEnableAll.Size = New-Object System.Drawing.Size -ArgumentList 95, 34
$btnEnableAll.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$form.Controls.Add($btnEnableAll)

$btnDisableAll = New-Object System.Windows.Forms.Button
$btnDisableAll.Text = 'Disable All'
$btnDisableAll.Location = New-Object System.Drawing.Point -ArgumentList 295, 58
$btnDisableAll.Size = New-Object System.Drawing.Size -ArgumentList 95, 34
$btnDisableAll.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$form.Controls.Add($btnDisableAll)

$btnGpUpdate = New-Object System.Windows.Forms.Button
$btnGpUpdate.Text = 'Run gpupdate /force'
$btnGpUpdate.Location = New-Object System.Drawing.Point -ArgumentList 400, 58
$btnGpUpdate.Size = New-Object System.Drawing.Size -ArgumentList 140, 34
$btnGpUpdate.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left
$form.Controls.Add($btnGpUpdate)

$lblSummary = New-Object System.Windows.Forms.Label
$lblSummary.Text = 'No checks have been run yet.'
$lblSummary.Location = New-Object System.Drawing.Point -ArgumentList 550, 64
$lblSummary.Size = New-Object System.Drawing.Size -ArgumentList 560, 25
$lblSummary.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$form.Controls.Add($lblSummary)

$dataGridView = New-Object System.Windows.Forms.DataGridView
$dataGridView.Location = New-Object System.Drawing.Point -ArgumentList 20, 105
$dataGridView.Size = New-Object System.Drawing.Size -ArgumentList 1090, 580
$dataGridView.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$dataGridView.AllowUserToAddRows = $false
$dataGridView.AllowUserToDeleteRows = $false
$dataGridView.RowHeadersVisible = $false
$dataGridView.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::AllCells
$dataGridView.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$dataGridView.MultiSelect = $false

# Add Columns with correct properties & widths
$colToggle = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
$colToggle.Name = "Enforce"
$colToggle.HeaderText = "Enforce"
$colToggle.Width = 70
$dataGridView.Columns.Add($colToggle) | Out-Null

$dataGridView.Columns.Add("Status", "Status") | Out-Null
$dataGridView.Columns["Status"].Width = 110

$dataGridView.Columns.Add("Id", "ID") | Out-Null
$dataGridView.Columns["Id"].Width = 75

$dataGridView.Columns.Add("Version", "CIS Version") | Out-Null
$dataGridView.Columns["Version"].Width = 85

$dataGridView.Columns.Add("Title", "Setting Title") | Out-Null
$dataGridView.Columns["Title"].Width = 550

$dataGridView.Columns.Add("Expected", "Expected") | Out-Null
$dataGridView.Columns["Expected"].Width = 80

$dataGridView.Columns.Add("Actual", "Actual") | Out-Null
$dataGridView.Columns["Actual"].Width = 80

$form.Controls.Add($dataGridView)

$btnRun.Add_Click({
    Invoke-ComplianceRun
})

$btnGpUpdate.Add_Click({
    try {
        $cursor = [System.Windows.Forms.Cursor]::Current
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
        
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "gpupdate.exe"
        $processInfo.Arguments = "/force"
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true

        $process = [System.Diagnostics.Process]::Start($processInfo)
        $process.WaitForExit()
        
        [System.Windows.Forms.Cursor]::Current = $cursor
        [System.Windows.Forms.MessageBox]::Show("Group Policy update completed successfully.", "gpupdate /force", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        
        Invoke-ComplianceRun
    }
    catch {
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
        [System.Windows.Forms.MessageBox]::Show("Failed to execute gpupdate: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
})

function Apply-SettingChange {
    param($check, $isChecked)
    try {
        # 1. Update live registry path
        if (-not (Test-Path $check.Path)) {
            New-Item -Path $check.Path -Force | Out-Null
        }
        
        if ($check.Id -in @('1.15.2', '1.15.3', '1.15.4')) {
            $targetValue = if ($isChecked) { "$($check.ExpectedValue)" } else { "6" }
            Set-ItemProperty -Path $check.Path -Name $check.PropertyName -Value $targetValue -Type String -ErrorAction Stop
        }
        else {
            $targetValue = if ($isChecked) { $check.ExpectedValue } else { if ($check.ExpectedValue -eq 1) { 0 } else { 1 } }
            Set-ItemProperty -Path $check.Path -Name $check.PropertyName -Value $targetValue -Type DWord -ErrorAction Stop
        }

        # 2. Update local Group Policy Registry.pol backing store
        $hivePath = $check.Path -replace '^HKLM:\\', ''
        $polFilePath = "$env:systemroot\System32\GroupPolicy\Machine\registry.pol"
        
        $polDir = Split-Path $polFilePath -Parent
        if (-not (Test-Path $polDir)) {
            New-Item -Path $polDir -ItemType Directory -Force | Out-Null
        }

        if (Get-Command Set-PolicyFileEntry -ErrorAction SilentlyContinue) {
            $polType = if ($check.Id -in @('1.15.2', '1.15.3', '1.15.4')) { "String" } else { "DWord" }
            $polData = if ($isChecked) { $check.ExpectedValue } else { if ($check.Id -in @('1.15.2', '1.15.3', '1.15.4')) { "6" } else { if ($check.ExpectedValue -eq 1) { 0 } else { 1 } } }
            Set-PolicyFileEntry -Path $polFilePath -Key $hivePath -ValueName $check.PropertyName -Data $polData -Type $polType -ErrorAction SilentlyContinue
        }

        return $true
    }
    catch {
        return $false
    }
}

$btnEnableAll.Add_Click({
    $script:isUpdatingGrid = $true
    $failedCount = 0
    foreach ($i in 0..($script:Checks.Count - 1)) {
        $check = $script:Checks[$i]
        $success = Apply-SettingChange -check $check -isChecked $true
        if ($success) {
            $dataGridView.Rows[$i].Cells[0].Value = $true
        } else {
            $failedCount++
        }
    }
    $script:isUpdatingGrid = $false
    Invoke-ComplianceRun
    if ($failedCount -gt 0) {
        [System.Windows.Forms.MessageBox]::Show("Completed with $failedCount errors applying configurations.", "Batch Enable", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    } else {
        [System.Windows.Forms.MessageBox]::Show("Successfully enabled and persisted all benchmark settings.", "Batch Enable", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    }
})

$btnDisableAll.Add_Click({
    $script:isUpdatingGrid = $true
    $failedCount = 0
    foreach ($i in 0..($script:Checks.Count - 1)) {
        $check = $script:Checks[$i]
        $success = Apply-SettingChange -check $check -isChecked $false
        if ($success) {
            $dataGridView.Rows[$i].Cells[0].Value = $false
        } else {
            $failedCount++
        }
    }
    $script:isUpdatingGrid = $false
    Invoke-ComplianceRun
    if ($failedCount -gt 0) {
        [System.Windows.Forms.MessageBox]::Show("Completed with $failedCount errors applying configurations.", "Batch Disable", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    } else {
        [System.Windows.Forms.MessageBox]::Show("Successfully disabled and persisted all benchmark settings.", "Batch Disable", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    }
})

$dataGridView.Add_CurrentCellDirtyStateChanged({
    if ($dataGridView.IsCurrentCellDirty) {
        $dataGridView.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
    }
})

$dataGridView.Add_CellValueChanged({
    param($sender, $e)
    if ($script:isUpdatingGrid) { return }
    if ($e.ColumnIndex -eq 0 -and $e.RowIndex -ge 0) {
        $check = $script:Checks[$e.RowIndex]
        $isChecked = [bool]$dataGridView.Rows[$e.RowIndex].Cells[0].Value
        $success = Apply-SettingChange -check $check -isChecked $isChecked
        if (-not $success) {
            [System.Windows.Forms.MessageBox]::Show("Failed to update setting.", "Remediation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
        Invoke-ComplianceRun
    }
})

Invoke-ComplianceRun

[System.Windows.Forms.Application]::Run($form)