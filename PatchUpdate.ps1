# -----------------------------------------------------------------------------------------
# Name: Monthly.ps1
# Purpose: Script for applying COTS updates and Microsoft hotfixes
#
# Version: 3.0     August 2019
# -----------------------------------------------------------------------------------------
Set-StrictMode -Version 2
[string]$discTitle="August 2019"

# -----------------------------BEGIN FUNCTIONS-------------------------------------------------------------

 # References:
 # https://portal.msrc.microsoft.com/en-us/security-guidance/summary
 # https://www.ghacks.net/tag/windows-update/

function Win10_1709_do_hotfixes([string]$currDir)
{
  $myArgs="/quiet /norestart"
  
  Write-Host "Installing $discTitle OS update"
  #No Adobe Flash Update August 2019
  #No Service Stack Update August 2019
  #Hotfixes
  Start-Process -Wait -FilePath "$currDir\windows10.0-kb4512516-x64_ff073f3c79f9bffd9e9ac4575fd4be1d336f8b74.msu" -ArgumentList $myArgs | out-null

}

function Win10_1607_do_hotfixes([string]$currDir)
{
  $myArgs="/quiet /norestart"
  
  Write-Host "Installing $discTitle OS update"
  #No Adobe Flash Update August 2019
  #No Service Stack Update August 2019
  #Hotfixes
  Start-Process -Wait -FilePath "$currDir\windows10.0-kb4512517-x64_81ba5a17cf768a54489faf28ba3a3eca3c0c36d5.msu" -ArgumentList $myArgs | out-null
   
}

function Win2016_do_hotfixes([string]$currDir)
{
  $myArgs="/quiet /norestart"
  
  Write-Host "Installing $discTitle OS update"
  #No Adobe Flash Update August 2019
  #No Service Stack Update August 2019
  #Hotfixes
  Start-Process -Wait -FilePath "$currDir\windows10.0-kb4512517-x64_81ba5a17cf768a54489faf28ba3a3eca3c0c36d5.msu" -ArgumentList $myArgs | out-null
}

# Current configuration uses Office 2016
function Office2016_do_hotfixes([string]$currDir)
{
  $myArgs="/q:a /r:n"
  Write-Host "Installing $discTitle Office updates"
  Start-Process -Wait -FilePath "$currDir\word2016-kb4475540-fullfile-x64-glb.exe" -ArgumentList $myArgs | out-null
  Start-Process -Wait -FilePath "$currDir\ace2016-kb4475538-fullfile-x64-glb.exe" -ArgumentList $myArgs | out-null
  Start-Process -Wait -FilePath "$currDir\outlook2016-kb4475553-fullfile-x64-glb.exe" -ArgumentList $myArgs | out-null
 
}

# Current configuration uses SQL 2016
function Sql2016_do_hotfixes([string]$currDir)
{
  #$myArgs="/IAcceptSqlServerLicenseTerms /AllInstances /QuietSimple"
  #$currentVer=VersionSql2016
  #if ($currentVer -ne "SP2")
  {
    #Write-Host "Installing SQL 2016 update SP2"
    #$null=Start-Process -Wait -FilePath "$currDir\SQLServer2016SP2-KB4052908-x64-ENU.exe" -ArgumentList $myArgs | out-null  
  }

  #$patchLvl=PatchLevelSql2016Tc2s
  #if ($patchLvl -ne "SP2CU1")
  {
    #Write-Host "Installing SQL 2016 update CU1 (for SP2)"
    #$null=Start-Process -Wait -FilePath "$currDir\SQLServer2016-KB4135048-x64.exe" -ArgumentList $myArgs | out-null
    #Write-Host "Done." -ForegroundColor Green
  }
  #else { Write-Host "SQL 2016 CU1 (for SP2) already installed." }
}

#Adobe Reader Patch/Update 
function inspect_Reader
{
  Write-Host "`n`nInstall/Patch Adobe Reader DC Classic"
  pushd
  cd Adobe
  .\InstAdobe.ps1
  popd
} # end inspect_Reader

# ---------------------------BEGIN 'MAIN'------------------------------------------------------------------

# Load common functions
[string]$currDir=Split-Path $MyInvocation.MyCommand.Definition -Parent
. "$currDir\Scripts\SecurityFunctions.ps1"
. "$currDir\Scripts\IniConfigUtils.ps1"
  
# Init variables from ini file
[string]$msrtVer=get-configured-item 'msrt' "Scripts"
[string]$the_log_dir=get-configured-item 'logDir' "Scripts"
[string]$the_quarter = get-configured-item 'quarter' "Scripts"
[string]$the_year = get-configured-item 'year' "Scripts"
[string]$shortTitle=$the_quarter + ' ' + $the_year  # was: "M1 2018"
[string]$longerTitle="TMPC Monthly Security: ($shortTitle)" 


# start a transcript file
$transcriptFile = startTranscriptLogFile -coreName "Monthly" "Scripts"

# Disable File Security  
$env:SEE_MASK_NOZONECHECKS = 1  

# Disable cert checks
$vencoreTapestryValue=146944
reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" /v "STATE" /f | out-null
Write-Host "Disabling certificate revocation checks."
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" /v "STATE" /t REG_DWORD /d $vencoreTapestryValue /f | out-null

Write-Host "Disabling smartscreen"
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f | out-null

$compDomain=get-WmiObject Win32_ComputerSystem | Select "PartOfDomain"
[bool]$isDomain=($compDomain.PartOfDomain -eq $true) 
if ($isDomain)   
{ Write-Host "Windows domain membership identified." -ForegroundColor Green }
else
{
  Write-Host "Not a member of a windows domain." -ForegroundColor Green
  Write-Host "  Set (force) the current network profile to private."
  Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue 
  
  Write-Host "  Reinspect network profile: " -NoNewline
  Get-NetConnectionProfile | select NetworkCategory
  Write-Host ""
}

# Apply SQL hotfixes
#if (isSql2016)
#	{Sql2016_do_hotfixes $currDir}

# Apply Adobe Reader update (if needed)
inspect_Reader

# Apply OS hotfixes
if (isWin10_1607)
	{Win10_1607_do_hotfixes $currDir}
if (isWin10_1511)
  {Win10_1511_do_hotfixes $currDir}
if (isWin10_1709)
	{Win10_1709_do_hotfixes $currDir}
if (isWin2016)
	{Win2016_do_hotfixes $currDir}

# Apply Office hotfixes
if (isOffice2016)
	{Office2016_do_hotfixes $currDir}

# Restore zone checks
$env:SEE_MASK_NOZONECHECKS = 0

# Restore cert checks V-7061, V-7062, V-7064, V-7065, V-7066, V-31212, V-31307, V-32808, V-46477  (STIG calls for 65536)
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" /v "STATE" /t REG_DWORD /d 65536 /f | out-null

# stop transcript
endTranscriptLogFile -file $transcriptFile 

.\Scripts\FullScreenPause.ps1 "Installation Complete. A reboot is always a good idea..."