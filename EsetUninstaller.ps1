$tempDir = "C:\Temp\kScriptEsetUninstaller\"
$preper = "$($tempDir)Redy.txt"
$networkSettingsFilePath = "$($tempDir)NetworkSettings.txt"
$uacSettingsFilePath = "$($tempDir)uacSettings.txt"
$reboot2SafeModeFilePath = "$($tempDir)Reboot2SafeMode.cmd"
$reboot2NormalModeFilePath = "$($tempDir)Reboot2NormalMode.cmd"
$runCmdFilePath = "$($tempDir)Run.cmd"
$scriptFilePath = "$($tempDir)EsetUninstaller.ps1"
$pingFilePath = "$($tempDir)Ping.cmd"
$esetUninstallerDownloadUrl = "https://download.eset.com/com/eset/tools/installers/eset_apps_remover/latest/esetuninstaller.exe"
$anyDeskDownloadUrl = "https://download.eset.com/com/eset/tools/installers/eset_apps_remover/latest/esetuninstaller.exe"
$esetUninstallerFilePath = "$($tempDir)esetuninstaller.exe"
$anyDeskFilePath = "$($tempDir)AnyDesk.exe"
$executionPolicyFilePath = "$($tempDir)executionPolicy.txt"
$stageFilePath = "$($tempDir)stage.txt"

$UserName = "kEsetUninstaller"
$FullName = "kEsetUninstaller"
$Password = "Aa102030"

function Download(){
    $tls = [System.Net.ServicePointManager]::SecurityProtocol
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $esetUninstallerDownloadUrl -OutFile $esetUninstallerFilePath
    Invoke-WebRequest -Uri $anyDeskDownloadUrl -OutFile $anyDeskFilePath
    [System.Net.ServicePointManager]::SecurityProtocol = $tls
}
function SaveNetworkSettings(){
    netsh -c interface dump > $networkSettingsFilePath
}
function ResotreNetworkSettings(){
    netsh -f $networkSettingsFilePath
}

function RebootSafeMode(){
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\Splashtop Inc." /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\SplashtopRemoteService" /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\AteraAgent" /f
    REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "*Run.cmd" /t REG_SZ /d "$($runCmdFilePath)" /f

    "PowerShell -ExecutionPolicy Unrestricted -File $($scriptFilePath)" | Set-Content -Path $runCmdFilePath -Encoding Ascii

    RunAsAdmin $reboot2SafeModeFilePath 

   # bcdedit /set {current} safeboot network
   # shutdown -r -f -t 30
}

function CreateReboot2NormalModeFile(){
$s = "bcdedit /deletevalue {current} safeboot"
$s += [System.Environment]::NewLine + "shutdown -r -f -t 30"
$s | Set-Content -Path $reboot2NormalModeFilePath -Encoding Ascii

#"bcdedit /deletevalue {current} safeboot" > $reboot2NormalModeFilePath
#"shutdown -r -f -t 30" >> $reboot2NormalModeFilePath
}
function CreateReboot2SafeModeFile(){

$s = "bcdedit /set {current} safeboot network"
$s += [System.Environment]::NewLine + "shutdown -r -f -t 30"

$s | Set-Content -Path $reboot2SafeModeFilePath -Encoding Ascii

#"bcdedit /deletevalue {current} safeboot" > $reboot2NormalModeFilePath
#"shutdown -r -f -t 30" >> $reboot2NormalModeFilePath
}
function RunAsAdmin($path){
    #call $reboot2NormalModeFilePath
    $cred = Get-AdminCredential
    Start-Process  -Credential $cred -FilePath $path 
}
function Reboot2NormalMode(){
    RunAsAdmin $reboot2NormalModeFilePath 
}
function UnInstall(){
"1" > "$($tempDir)UnInstall.txt"
}
function Cleanup(){
    
    if (-not (Test-Path $tempDir )) {
        return
    }
    $policy = Get-Content -Path $executionPolicyFilePath |  ConvertFrom-Json
    for($i = 0; $i -lt $policy.length; $i++){ 
        $policy[$i]
        [Microsoft.PowerShell.ExecutionPolicy] $executionPolicy = [Microsoft.PowerShell.ExecutionPolicy]$policy[$i].ExecutionPolicy
        [Microsoft.PowerShell.ExecutionPolicyScope]$scope = [Microsoft.PowerShell.ExecutionPolicyScope]$policy[$i].Scope
        Set-ExecutionPolicy -ExecutionPolicy $executionPolicy -Scope $scope -Force -ErrorAction SilentlyContinue 
    }
    Remove-LocalUser -Name $UserName
    Start-Sleep 5
    Remove-Item -LiteralPath $tempDir  -Force -Recurse
}

function CreatePing2GoogleFile()
{
    'cmd /c ping google.com -n 1' | Set-Content -Path $pingFilePath
}
function Preper(){
    if ((Test-Path $preper) ) {
        return
    }

    New-Item -ItemType Directory -Path $tempDir -Force 
    Get-ExecutionPolicy -List | ConvertTo-Json | Set-Content -Path $executionPolicyFilePath -Force
    "PowerShell -ExecutionPolicy Unrestricted -File $($scriptFilePath)" | Set-Content -Path $runCmdFilePath -Encoding Ascii
    Save-UACSettings
    Add-LocalAdminUser
    CreateReboot2SafeModeFile
    CreatePing2GoogleFile
    RunPing
    Set-UAC
}
function Get-AdminCredential(){
    $pass = ConvertTo-SecureString $Password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential ($UserName, $pass)
}
function RunPing(){
    RunAsAdmin $pingFilePath 
}
 #REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /f

function Add-LocalAdminUser(){
    $secureStringPassword = $Password | ConvertTo-SecureString -AsPlainText -Force
    New-LocalUser $UserName -Password $secureStringPassword -FullName $FullName 
    $HN=hostname
    Add-LocalGroupMember -Group 'Administrators' -Member $HN\$UserName
}
Function Check-RunAsAdministrator()
{
  #Get current user context
  $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  
  #Check user is running the script is member of Administrator Group
  if($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
  {
       #[System.Windows.MessageBox]::Show('Script is running with Administrator privileges!')
       Write-host "Script is running with Administrator privileges!"
  }
  else
    {
      #$credential = New-Object System.Management.Automation.PsCredential("Domain\UserID", (ConvertTo-SecureString "Password" -AsPlainText -Force))
      #Start-Process powershell -Credential $credential -NoNewWindow

        #[System.Windows.MessageBox]::Show('Script is running !')
       #Create a new Elevated process to Start PowerShell
       $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
 
       # Specify the current script path and name as a parameter
       $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
 
       #Set the Process to elevated
       $ElevatedProcess.Verb = "runas"
 
       #Start the new elevated process
       [System.Diagnostics.Process]::Start($ElevatedProcess)
 
       #Exit from the current, unelevated, process
       Exit
 
    }
}
function Save-UACSettings(){
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $filter="ConsentPromptBehaviorAdmin|ConsentPromptBehaviorUser|EnableInstallerDetection|EnableLUA|EnableVirtualization|PromptOnSecureDesktop|ValidateAdminCodeSignatures|FilterAdministratorToken"
    (Get-ItemProperty $path).psobject.properties | where {$_.name -match $filter} | select name,value | ConvertTo-Json | Set-Content -Path $uacSettingsFilePath -Force
}
function Restore-UACSettings(){
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacSettings = Get-Content -Path $uacSettingsFilePath |  ConvertFrom-Json
    for($i = 0; $i -lt $uacSettings.length; $i++){ 
        $name = $uacSettings[$i].Name
        $value = $uacSettings[$i].Value
        New-ItemProperty -Path $path -Name $name -Value $value -PropertyType DWORD -Force | Out-Null -ErrorAction SilentlyContinue 
    }
}

function Set-UAC(){
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    New-ItemProperty -Path $path -Name 'ConsentPromptBehaviorAdmin' -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $path -Name 'ConsentPromptBehaviorUser' -Value 3 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $path -Name 'EnableInstallerDetection' -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $path -Name 'EnableLUA' -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $path -Name 'EnableVirtualization' -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $path -Name 'PromptOnSecureDesktop' -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $path -Name 'ValidateAdminCodeSignatures' -Value 0 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $path -Name 'FilterAdministratorToken' -Value 0 -PropertyType DWORD -Force | Out-Null
}
function Main(){
     Check-RunAsAdministrator
     Preper
    if (-not (Test-Path $stageFilePath) ) {
        "1">"$($stageFilePath)"
        Start-Sleep 5
    }
    [int]$stage = Get-Content -Path $stageFilePath

    if ($stage -eq 1){
        Write-Host "Stage 1"
        SaveNetworkSettings
        Download
        CreateReboot2NormalModeFile
        "1">"$($tempDir)1.txt"
        ($stage + 1)  > "$($stageFilePath)"
        RebootSafeMode
    }
    if ($stage -eq 2){
        Write-Host "Stage 2"
        UnInstall
        #ResotreNetworkSettings
        Reboot2NormalMode
        "2">"$($tempDir)2.txt"
        ($stage + 1)  > "$($stageFilePath)"
    }
    if ($stage -eq 3){
        Restore-UACSettings
        Write-Host "Stage 3"
        "3">"$($tempDir)3.txt"
        ($stage + 1)  > "$($stageFilePath)"
        Start-Sleep 5
        Cleanup
    }
}
main > $null
