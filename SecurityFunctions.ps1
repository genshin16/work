. "$(Split-Path $MyInvocation.MyCommand.Definition -Parent)\CommonFunctions.ps1"
# -----------------------------------------------------------------------------------------
# Name: SecurityFunctions.ps1
# Purpose: Misc Functions for the Quarterly Disc for Windows10/2012R2/2016 
# Version: 1.0 - Oct 2019
# -----------------------------------------------------------------------------------------
#Requires -Version 4.0
$script:CG_ProductList_Filled=$false

function isWin10_1709()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  return ((isWin10) -and ((getWin10Release) -eq "1709"))
}

function isWin10_1607()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  return ((isWin10) -and ((getWin10Release) -eq "1607"))
}

function isWin10_1511()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters

  return ((isWin10) -and ((getWin10Release) -eq "1511"))
}

function getWin10Release()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $versionKey=Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
  $releaseVer=$versionKey | Select-Object "ReleaseId"
  return $releaseVer.ReleaseId
}

function isWin10()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $versionKey=Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
  $prodName=$versionKey | Select-Object "ProductName"
  if ($prodName.ProductName.StartsWith("Windows 10"))
    {return $true}
  return $false
}

function isWin2016()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  if (IsServerOS)
  {
    $versionKey=Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $mainVersion=$versionKey | Select-Object "CurrentVersion" # Win7/2008R2=6.1, Win8/2012=6.2, Win8.1/10/2012R2/2016=6.3
    if ($mainVersion.CurrentVersion -eq "6.4")  
      { return $true }   # only preview builds were 6.4
    if ($mainVersion.CurrentVersion -eq "6.3")
    { 
      $prodName=$versionKey | Select-Object "ProductName" 
      return $prodName.ProductName.Contains("2016") 
    }
  }
  return $false
}

function isWin2012R2()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  if (IsServerOS)
  {
    $versionKey=Get-ItemProperty "hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $mainVersion=$versionKey | Select-Object "CurrentVersion" # Win7/2008R2=6.1, Win8/2012=6.2, Win8.1/10/2012R2,2016=6.3
    if ($mainVersion.CurrentVersion -eq "6.3")
    { 
      $prodName=$versionKey | Select-Object "ProductName" 
      return $prodName.ProductName.Contains("2012") 
    }
  }
  return $false
}

function isIE11()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $ieKey="hklm:\SOFTWARE\Microsoft\Internet Explorer"
  if (test-path $ieKey)
  {
    $ieVersion=(Get-ItemProperty $ieKey).Version
    if ($ieVersion.Contains("9.11.") -or $ieVersion.Contains("11.0."))
      { return $true }
  }
  return $false
}

function isOffice2013()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $ofcKey="hklm:\SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Common\ProductVersion"
  if (test-path $ofcKey)
  {
    $ofcProd=(Get-ItemProperty $ofcKey).LastProduct
    if ($ofcProd.Contains("15.0.4569"))
      { return $true }
  }
  return $false
}

function isOffice2016()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $ofcKey="hklm:\SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\ProductVersion"
  if (test-path $ofcKey)
  {
    $ofcProd=(Get-ItemProperty $ofcKey).LastProduct
    if ($ofcProd.Contains("16.0"))
      { return $true }
  }
  return $false
}

# This function returns a boolean, based on the results from the first SQL instance it finds
function isSql2014()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $instances = "TC2S","ISAT","TPS","SQLEXPRESS","BKUPEXEC","PLC" 
  foreach ($instance in $instances)
  {
    $sqlKey="hklm:\software\microsoft\Microsoft SQL Server\"+$instance+"\MSSQLServer\CurrentVersion"
    if (test-path $sqlKey)
    {  
      $buildNum=(Get-ItemProperty $sqlKey).CurrentVersion
      if ($buildNum.StartsWith("12"))
        {return $true}
    }
  }
  return $false
}

# This function returns a string, based on the results from the passed SQL instance.
# If the SQL instance is not provided, it checks several, and returns the first SQL instance it finds. 
function VersionSql2014()
{
  [CmdletBinding()]
  param([Parameter(Mandatory=$false)][string]$instance)

  if (-not([System.string]::IsNullOrEmpty($instance)))
  {$instances = @($instance) }
  else
  {$instances = "TC2S","ISAT","TPS","SQLEXPRESS","BKUPEXEC","PLC"}

  foreach ($instance in $instances)
  {
    $sqlKey="hklm:\software\microsoft\Microsoft SQL Server\"+$instance+"\MSSQLServer\CurrentVersion"
    if (test-path $sqlKey)
    { 
      # Convert PS object, to an ordinary string
      $buildNum=(Get-ItemProperty $sqlKey).CurrentVersion
      
      # http://sqlserverbuilds.blogspot.com/
      # http://support.microsoft.com/kb/321185
      IF (($buildNum -eq "12.0.2000.8") -or ($buildNum -eq "12.0.2000.80"))
      { return "RTM" }

      IF (($buildNum -eq "12.0.4100.1") -or ($buildNum -eq "12.1.4100.1"))
      { return "SP1" }

      IF (($buildNum -eq "12.0.5000.0") -or ($buildNum -eq "12.1.5000.1") -or ($buildNum -eq "12.2.5000.1"))
      { return "SP2" }

      return "Unknown"
    }
  }
  return "None"
}

# This function returns a string, based on a particular SQL instance only
function PatchLevelSql2014()
{
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$instance)

  $setupKey="hklm:\software\microsoft\Microsoft SQL Server\MSSQL12.$instance\Setup"
  if (test-path $setupKey)
  { 
    # Convert PS object, to an ordinary string
    $patchLevel=(Get-ItemProperty $setupKey).PatchLevel
      
    # http://sqlserverbuilds.blogspot.com/
    # http://support.microsoft.com/kb/321185  or   https://support.microsoft.com/en-us/kb/2936603
    IF (($patchLevel -eq "12.0.2000.8") -or ($patchLevel -eq "12.0.2000.80")) 
    { return "RTM" }
    
    IF ($patchLevel -eq "12.0.2430.0")  
    { return "CU4" }

    # The faulty SP1 was 12.0.4050.0
    IF (($patchLevel -eq "12.0.4100.1") -or ($patchLevel -eq "12.1.4100.1"))
    { return "SP1" }

    IF (($patchLevel -eq "12.0.4416.1") -or ($patchLevel -eq "12.1.4416.1"))  
    { return "SP1CU1" }

    # 5.0.2 originally used SP1CU2
    IF (($patchLevel -eq "12.0.4422.1") -or ($patchLevel -eq "12.1.4422.1") -or ($patchLevel -eq "12.1.4422.0"))  
    { return "SP1CU2" }

    # 5.0.2 FIB uses SP1CU6
    IF (($patchLevel -eq "12.0.4449.1") -or ($patchLevel -eq "12.1.4449.1") -or ($patchLevel -eq "12.1.4449.0"))  
    { return "SP1CU6_april" }

    # 5.0.2 FIB uses SP1CU6. Thanks Microsoft, two build called "CU6".
    IF (($patchLevel -eq "12.0.4457.1") -or ($patchLevel -eq "12.1.4457.1") -or ($patchLevel -eq "12.1.4457.0"))  
    { return "SP1CU6_may" }

    # Post FIB... Q416
    IF (($patchLevel -eq "12.0.5000.0") -or ($patchLevel -eq "12.1.5000.1") -or ($patchLevel -eq "12.2.5000.0"))
      { return "SP2" }
      
    # MS16-136,   KB3194716 / KB3194714
    IF (($patchLevel -eq "12.0.5203.0") -or ($patchLevel -eq "12.1.5203.1") -or ($patchLevel -eq "12.2.5203.0"))
      { return "SP2_MS16-136" }

    # KB4019093 released August 2017 (aka CU5 released in July). Yeah. Thanks microsoft, that's not confusing is it.
    IF (($patchLevel -eq "12.0.5207.0") -or ($patchLevel -eq "12.1.5207.1") -or ($patchLevel -eq "12.2.5207.0"))
      { return "SP2_Aug17" }

    # KB4032541 also released August 2017 (thanks Microsoft). At least the build # is higher.
    IF (($patchLevel -eq "12.0.5556.0") -or ($patchLevel -eq "12.1.5556.1") -or ($patchLevel -eq "12.2.5556.0"))
      { return "SP2CU7" }

    # KB4052725 (18-Jan-2018) is the same as KB4057117 (16-Jan-2018). Thanks again Microsoft.
    IF (($patchLevel -eq "12.0.5571.1") -or ($patchLevel -eq "12.1.5571.1") -or ($patchLevel -eq "12.2.5571.0")) 
      { return "SP2CU10" }

    # CU11 released 19-Mar-2018.
    IF (($patchLevel -eq "12.0.5579.0") -or ($patchLevel -eq "12.1.5579.1") -or ($patchLevel -eq "12.2.5579.0"))
      { return "SP2CU11" }

  }
  return "Unknown"
}

function isSql2016()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $instances = "TC2S","SQLEXPRESS","BKUPEXEC","PLC","ISAT","TPS" 
  foreach ($instance in $instances)
  {
    $sqlKey="hklm:\software\microsoft\Microsoft SQL Server\"+$instance+"\MSSQLServer\CurrentVersion"
    if (test-path $sqlKey)
    {  
      $buildNum=(Get-ItemProperty $sqlKey).CurrentVersion
      if ($buildNum.StartsWith("13"))
        {return $true}
    }
  }
  return $false
}

function VersionSql2016()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $instances = "TC2S","SQLEXPRESS","BKUPEXEC","PLC","ISAT","TPS"
  foreach ($instance in $instances)
  {
    $sqlKey="hklm:\software\microsoft\Microsoft SQL Server\MSSQL13."+$instance+"\Setup"
    if (test-path $sqlKey)
    { 
      # Convert PS object, to an ordinary string
      $buildNum=(Get-ItemProperty $sqlKey).Version
      
      # http://sqlserverbuilds.blogspot.com/
      # http://support.microsoft.com/kb/321185
      IF (($buildNum -eq "13.0.1601.5") -or ($buildNum -eq "13.1.1601.5"))
      { return "RTM" }

      IF (($buildNum -eq "13.0.4001.0") -or ($buildNum -eq "13.1.4001.0"))
      { return "SP1" }

      IF (($buildNum -eq "13.0.5026.0") -or ($buildNum -eq "13.1.5026.0"))
      { return "SP2" }

      return "Unknown"
    }
  }
  return "None"
}

function PatchLevelSql2016Tc2s()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $setupKey="hklm:\software\microsoft\Microsoft SQL Server\MSSQL13.TC2S\Setup"
  if (test-path $setupKey)
  { 
    # Convert PS object, to an ordinary string
    $patchLevel=(Get-ItemProperty $setupKey).PatchLevel
      
    # http://sqlserverbuilds.blogspot.com/
    # http://support.microsoft.com/kb/321185  or   https://support.microsoft.com/en-us/kb/2936603
    IF (($patchLevel -eq "13.0.1601.5") -or ($patchLevel -eq "13.1.1601.5")) 
    { return "RTM" }
     
    IF (($patchLevel -eq "13.0.4001.0") -or ($patchLevel -eq "13.1.4001.0"))
    { return "SP1" } 

    IF (($patchLevel -eq "13.0.4446.0") -or ($patchLevel -eq "13.1.4446.0"))
    { return "SP1CU4" } 

    IF (($patchLevel -eq "13.0.5149.0") -or ($patchLevel -eq "13.1.5149.0"))
    { return "SP2CU1" }
  }
  return "Unknown"
}

function isIIS()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  [bool]$w3svcInstalled = $false
  IF (test-path "hklm:\SOFTWARE\Microsoft\InetStp")
  { 
    IF (test-path "hklm:\SOFTWARE\Microsoft\InetStp\Components")
    { 
      $myProp = Get-ItemProperty "hklm:\SOFTWARE\Microsoft\InetStp\Components" -ea 0
      if ($myProp -ne $null)
      { $w3svcInstalled = $myProp.W3SVC }
    }
  }
  
  # sometimes that false-positives!
  if ($w3svcInstalled)
  {
    # so, check for the 'service' to be registered too
    $w3svcInstalled=isSvcInstalled "W3SVC"
  }
  return $w3svcInstalled
}

function isFtp()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  [bool]$ftpInstalled = $false
  IF (test-path "hklm:\SOFTWARE\Microsoft\InetStp")
  { 
    IF (test-path "hklm:\SOFTWARE\Microsoft\InetStp\Components")
    { 
      $myProp = (Get-ItemProperty "hklm:\SOFTWARE\Microsoft\InetStp\Components").FTPSvc 
      if ($myProp -ne $null)
      {$ftpInstalled = $myProp}
    }
  }
  return $ftpInstalled
}

function isJava()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  [string]$javaExe="$env:ProgramData\Oracle\Java\javapath\java.exe"
  if (test-path $javaExe -ErrorAction SilentlyContinue)
  { return $true }
  return $false
}

function IsDomainPC 
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters

  $compDomain=get-WmiObject Win32_ComputerSystem | Select-Object "PartOfDomain"
  IF ($compDomain.PartOfDomain -eq $true) 
    { return $true }
  return $false
}

function IsServerOS()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $prodType = get-WmiObject Win32_OperatingSystem | Select-Object "ProductType"
  IF ($prodType.ProductType -eq 1) 
  { return $false }
  return $true
}

function IsFirefox()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  IF (test-path "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe" )  
  { return $true }
  return $false
}

function IsFilezilla()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  IF ((test-path "hklm:\SOFTWARE\Wow6432Node\FileZilla Client" ) -or 
     (test-path "hklm:\SOFTWARE\FileZilla Client" ))
    { return $true }
  return $false
}

function IsUsafToolbox60()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  IF (test-path "C:\Program Files (x86)\USAF\Toolbox\Toolbox.exe" )  
  { 
    $fileProps=Get-ItemProperty "C:\Program Files (x86)\USAF\Toolbox\Toolbox.exe" -ErrorAction SilentlyContinue
    if ($? -and ($fileProps -ne $null) -and ($fileProps.Version -eq "6.0.0.0")) 
    { return $true } 
  }
  return $false
}

function IsUsafToolbox62()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  IF (test-path "C:\Program Files (x86)\USAF\Toolbox\Toolbox.exe" )  
  { 
    $fileProps=Get-ItemProperty "C:\Program Files (x86)\USAF\Toolbox\Toolbox.exe" -ErrorAction SilentlyContinue
    if ($? -and ($fileProps -ne $null) -and ($fileProps.Version -eq "6.2.0.0")) 
    { return $true } 
  }
  return $false
}

function GetUsrSid([string]$UsrName)
{
  $colItems = get-WmiObject -query ("select * from Win32_UserAccount where LocalAccount=True and Name='" + $UsrName +"'")
  ForEach ($objItem in $colItems)
  { return $objItem.SID }
  # return sid for EVERYONE if not found
  return "S-1-1-0"
}

function New-Trustee($User)  
{  
    $t = (new-object management.managementclass win32_trustee).CreateInstance() 
    #$t.Domain = $env:COMPUTERNAME 
    $t.Domain = $null
    $t.Name = [string]$User
    $t.SIDString = GetUsrSid([string]$User)
    return $t  
}

function New-ACE($trustee, $Access, $Type, $Flags)  
{  
    $a = (new-object management.managementclass Win32_ace).CreateInstance() 
    $a.AccessMask = $Access  
    $a.AceType = $Type  
    $a.AceFlags = $Flags  
    $a.Trustee = $trustee  
    return $a  
}  
  
function Get-SecurityDescriptor($ACL)  
{  
    $sd = (new-object management.managementclass Win32_SecurityDescriptor).CreateInstance() 
    [System.Management.ManagementObject[]] $DACL = $ACL  
    $sd.DACL = $DACL  
    return $sd  
}  

function ShareExists ([string]$shareName)
{
  $checkShare = (Get-WmiObject Win32_Share -Filter "Name='$shareName'")  
  return ($checkShare -ne $null)
}

function new-win32Share ()
{
  param ([string]$shareName = $(throw "Please specify a name for the share" ),
         [string]$FolderPath = $(throw "Please specify a location for the share"),
         [string]$Comment = $(throw "Please specify a comment for the share"),
         [string]$User = $(throw "Please specify a user to own the share"))         
  $SHARE_FULL = 2032127     # 111110000000111111111
  $ACETYPE_ACCESS_ALLOWED = 0 
  $ACEFLAG_INHERIT_ACE = 2  
  $FILE_SHARE = 0 
  $maxAllowed = $null
  
  $trustee = New-Trustee $User 
  $ACE = New-ACE $trustee $SHARE_FULL $ACETYPE_ACCESS_ALLOWED $ACEFLAG_INHERIT_ACE      
  $access = Get-SecurityDescriptor $ACE  
  
  $wmishare = [WMIClass] "ROOT\CIMV2:Win32_Share"  
  # Create method documentation: http://msdn.microsoft.com/en-us/library/aa389393(v=VS.85).aspx
  $R = $wmishare.Create($FolderPath, $shareName, $FILE_SHARE, $maxAllowed, $Comment, "", $access)   
  
  if ($R.ReturnValue -eq 0) 
  { Write-Host "Share has been created." }
  ELSE
  { 
    Switch ($R.returnvalue) 
    {        
      0 {$rvalue = "Success"}        
      2 {$rvalue = "Access Denied"}             
      8 {$rvalue = "Unknown Failure"}             
      9 {$rvalue = "Invalid Name"}             
     10 {$rvalue = "Invalid Level"}             
     21 {$rvalue = "Invalid Parameter"}             
     22 {$rvalue = "Duplicate Share"}             
     23 {$rvalue = "Redirected Path"}             
     24 {$rvalue = "Unknown Device or Directory"}        
     25 {$rvalue = "Net Name Not Found"}    
    }
    Write-Host "Error while creating share: " $rvalue 
  } 
}

function AdminCheckAndPromote() 
{
  [CmdletBinding()]
   Param(
    [Parameter(Mandatory=$false,HelpMessage="When promoting, the new powershell should be in noninteractive mode")][bool]$Noninteractive=$false )
 
  if (-not (DoesCurrentUserHaveAdminPriv)) 
  {
    # from within a function, the 'MyInvocation' variable is null. So use "-1" to get invocation of parent, which must be the top level of a script (cannot be a function)
    $invocationCmd = ((Get-Variable MyInvocation -Scope 1).Value).MyCommand
    $workDir = Split-Path ($invocationCmd.Path)
    
    # prepend the current script with a command to change the working directory
    $command = "set-location `"" + $workDir + "`";. `"" + ($invocationCmd.Definition) + "`""
    $bytes = [Text.Encoding]::Unicode.GetBytes($command)
    $enc= [Convert]::ToBase64String($bytes)  
    try
    {
      $arguments = "-NoLogo -ExecutionPolicy Bypass"
      if ($Noninteractive)
      { $arguments += " -Noninteractive"}

      $arguments += " -EncodedCommand $enc"
      $null = Start-Process "$pshome\powershell.exe" -Verb runAs -ArgumentList $arguments -PassThru 
    } 
    catch
    {
      $Error[0] # Dump details about the last error
      Exit 1
    }
    Exit 0
  }
}

function removePasswordFilter
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  [string]$strKeyPath = "hklm:\System\CurrentControlSet\Control\LSA"
  [string]$strKeyName = "Notification Packages"
  [string]$newEnPasDll = "EnPasFltV2x64.dll"
  
  # get the list of password-filters
  $lsaSettings = get-item $strKeyPath
  $packages = $lsaSettings.GetValue($strKeyName)
  IF ($?) 
  { 
    [bool]$newDllConfigured = $false
    FOREACH ($strValue In $packages)
    {
      If ($strValue -eq $newEnPasDll )
      {
        Write-Host "  v2 DISA password filter detected"
        $newDllConfigured = $true
      }
    } # end loop thru password filters
  
    IF ($newDllConfigured)
    {
      Write-Host "  Removing v2 password filter from config" 
      $packages = @($packages | Where-Object {$_ -ne $newEnPasDll})
      Set-ItemProperty -Path $strKeyPath "$strKeyName" $packages
      Write-Host "  Password filter removed."  -ForegroundColor Green
    }
    else
    { Write-Host "  Password filter not detected."  -ForegroundColor Green }

  }
  ELSE
  { Write-Host "  Failed to review password filter settings." }
}

function Invoke-CleanupMgr()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  # Configure the cleanup manager, to erase files from the temp folders which haven't been accessed in 3 days or more. (Default=7) 
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v "LastAccess" /d 3 /f | out-null 

  Write-Host -nonewline "Running cleanup utility to wipe old install files."
  Write-Host "!!POTENTIALLY VERY TIME-CONSUMING!!" -ForegroundColor Yellow
  # Specify parameters group#64
  C:\Windows\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files"      /v "Priority"       /t REG_DWORD /d 64 /f
  C:\Windows\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" /v "StateFlags0064" /t REG_DWORD /d 2 /f
  C:\Windows\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files"     /v "StateFlags0064" /t REG_DWORD /d 2 /f
  C:\Windows\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Memory Dump Files"        /v "StateFlags0064" /t REG_DWORD /d 2 /f
  C:\Windows\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin"              /v "StateFlags0064" /t REG_DWORD /d 2 /f
  C:\Windows\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files"          /v "StateFlags0064" /t REG_DWORD /d 2 /f
  C:\Windows\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files"    /v "StateFlags0064" /t REG_DWORD /d 2 /f
  # if KB2852386 is installed, this should also get old hotfixes from the sxs folder
  C:\Windows\System32\reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup"           /v "StateFlags0064" /t REG_DWORD /d 2 /f
  # Apply cleanup according to the parameters group#64
  C:\WINDOWS\SYSTEM32\cleanmgr.exe /D C: /sagerun:64
  Start-Sleep -s 1
  pushd
  cd ..\COTS\AutoIt3
  $null=Start-Process Powershell.exe -WindowStyle Minimized -ArgumentList ".\handleCleanupMgr.ps1"
  popd
  $null = get-process | Where-Object {$_.ProcessName -eq "cleanmgr"} | Foreach-Object { $_.WaitForExit() }
  Write-Host " Cleanup utility completed."
}

# http://norphus.co.uk/2015/01/dcm-script-detect-office-activation-status-on-windows-7-and-activate-if-unactivated/
function IsOffice15Activated() # aka "Office 2013" to most people
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters

  [string]$scriptName=$null
  if (test-path "C:\Program Files (x86)\Microsoft Office\Office15\OSPP.VBS")
  { $scriptName="C:\Program Files (x86)\Microsoft Office\Office15\OSPP.VBS"}
  else {if (test-path "C:\Program Files\Microsoft Office\Office15\OSPP.VBS")
  { $scriptName="C:\Program Files\Microsoft Office\Office15\OSPP.VBS"}}

  if (($scriptName -eq $null) -or ($scriptName -eq ""))
  {
    Write-Host "Office 2013 not installed"
    return $false
  }
  
  cscript //E:vbscript //nologo "$scriptName" /dstatus | Out-File $env:temp\actstat.txt
  $ActivationStatus = $($Things = $(Get-Content $env:temp\actstat.txt -raw) `
                            -replace ":"," =" `
                            -split "---------------------------------------" `
                            -notmatch "---Processing--------------------------" `
                            -notmatch "---Exiting-----------------------------"
      $Things | ForEach-Object `
      {
        $Props = ConvertFrom-StringData -StringData ($_ -replace '\n-\s+')
        New-Object psobject -Property $Props  | Select-Object "SKU ID", "LICENSE NAME", "LICENSE DESCRIPTION", "LICENSE STATUS", "REMAINING GRACE"  
      })
 
  $Var = "Office Activated "
  for ($i=0; $i -le $ActivationStatus.Count-2; $i++) 
  {
    if ($ActivationStatus[$i]."LICENSE STATUS" -eq "---LICENSED---")
    { $Var = $Var + "OK " }
    else 
    { $Var = $Var + "Bad " }

    [string]$grace=$ActivationStatus[$i]."REMAINING GRACE"
    if ($grace -ne $null)
    {
      [int]$grace=($grace -split ' ')[0]
      if ($grace -lt 125)
      {  
        # we should relicense now
        $Var = $Var + "(short grace)"
      }
      else 
      { } # We'll re-license next quarter
    } # endif remaining grace specified
  } # end loop
 
  If ($Var -like "*Bad*") 
  {
    Write-Host "Office 2013 Not Activated"
    return  $false
  }

  If ($Var -like "*grace*") 
  {
    Write-Host "Office 2013 -- Grace period is short"
    return  $false
  }
  else
  {
    Write-Host "Office 2013 Activated"
    return $true
  }
} # end IsOffice15Activated

function IsOffice2016Activated()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters

  [string]$scriptName=$null
  if (test-path "C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS")
  { $scriptName="C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS"}
  else {if (test-path "C:\Program Files\Microsoft Office\Office16\OSPP.VBS")
  { $scriptName="C:\Program Files\Microsoft Office\Office16\OSPP.VBS"}}

  if (($scriptName -eq $null) -or ($scriptName -eq ""))
  {
    Write-Host "Office 2016 not installed"
    return $false
  }
  
  cscript //E:vbscript //nologo "$scriptName" /dstatus | Out-File $env:temp\actstat.txt
  $ActivationStatus = $($Things = $(Get-Content $env:temp\actstat.txt -raw) `
                            -replace ":"," =" `
                            -split "---------------------------------------" `
                            -notmatch "---Processing--------------------------" `
                            -notmatch "---Exiting-----------------------------"
      $Things | ForEach-Object `
      {
        $Props = ConvertFrom-StringData -StringData ($_ -replace '\n-\s+')
        New-Object psobject -Property $Props  | Select-Object "SKU ID", "LICENSE NAME", "LICENSE DESCRIPTION", "LICENSE STATUS", "REMAINING GRACE"
      })
 
  $Var = "Office Activated "
  for ($i=0; $i -le $ActivationStatus.Count-2; $i++) 
  {
    if ($ActivationStatus[$i]."LICENSE STATUS" -eq "---LICENSED---")
    { $Var = $Var + "OK " }
    else 
    { $Var = $Var + "Bad " }

    [string]$grace=$ActivationStatus[$i]."REMAINING GRACE"
    if ($grace -ne $null)
    {
      [int]$grace=($grace -split ' ')[0]
      if ($grace -lt 125)
      {  
        # we should relicense now
        $Var = $Var + "(short grace)"
      }
      else 
      { } # We'll re-license next quarter
    } # endif remaining grace specified
  } # end loop
 
  If ($Var -like "*Bad*") 
  {
    Write-Host "Office 2016 Not Activated"
    return  $false
  }

  If ($Var -like "*grace*") 
  {
    Write-Host "Office 2013 -- Grace period is short"
    return  $false
  }
  else
  {
    Write-Host "Office 2016 Activated"
    return $true
  }
} # end IsOffice2016Activated

function IsBackupExec2014()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  IF (test-path "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Symantec Backup Exec 14.1" )  
  { return $true }
  return $false
}

function IsBackupExec2016()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  IF (test-path "hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Veritas Backup Exec 16.0" )  
  { return $true }
  return $false
}

function IsBackupExec2014AtSp2()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  IF (test-path "hklm:\SOFTWARE\Symantec\Backup Exec For Windows\Backup Exec\14.1\Install" )
  {
    $mediaProperties=Get-ItemProperty "hklm:\SOFTWARE\Symantec\Backup Exec For Windows\Backup Exec\14.1\Install" -ErrorAction SilentlyContinue
    $mediaVer=$mediaProperties."Telemetry Media Version"
    IF (($mediaVer -ne $null) -and ($mediaVer -eq "2"))  
    { return $true }
  }
  return $false
}

function IsBackupExec2014AtHotfix126144()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $someFile="C:\Program Files\Symantec\Backup Exec\BeComSvc.exe" 
  IF (test-path $someFile )
  {
    $currentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$someFile").FileVersion
    IF (($currentVersion -ne $null) -and ($currentVersion -ge "14.1.1786.1126"))  
    { return $true }
  }
  return $false
}
function IsBackupExec2016AtHotfix124683()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $someFile="C:\Program Files\Veritas\Backup Exec\BeComSvc.exe" 
  IF (test-path $someFile )
  {
    $currentVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$someFile").FileVersion
    IF (($currentVersion -ne $null) -and ($currentVersion -ge "16.0.1142.1009"))  # OEM=16.0.1142.0    Hotfix124683=16.0.1142.1009
    { return $true }
  }
  return $false
}

# https://gist.github.com/alirobe/7f3b34ad89a159e6daa1
Function DisableIEEnhancedSecurity 
{
	Write-Host "Disabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
  #Disable ESC for admin users
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
  #Disable ESC for non-admin users
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
}

# https://gist.github.com/alirobe/7f3b34ad89a159e6daa1
# Enable Internet Explorer Enhanced Security Configuration (IE ESC)
Function EnableIEEnhancedSecurity 
{
	Write-Host "Enabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
	#Enable ESC for admin users
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
	#Enable ESC for non-admin users
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
}