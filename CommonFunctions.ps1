# -----------------------------------------------------------------------------------------
# Name: CommonFunctions.ps1
# Purpose: Misc Functions used by Quarterly disc and possibly MDS install and/or 
#          developer utilities.
#
# Version: 1.0     August 2019
# -----------------------------------------------------------------------------------------


function DoesCurrentUserHaveDebugPriv 
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $user = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]$user
  $principal.IsInRole("Debugger Users")
}

function DoesCurrentUserHaveBackupPriv 
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $user = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]$user
  $principal.IsInRole("Backup Operators")
}

function DoesCurrentUserHaveAdminPriv 
{
  $user = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]$user
  $principal.IsInRole("Administrators")
}

function DoesCurrentUserHaveAuditPriv()
{
  [CmdletBinding()]
  param() # enforce that this function takes no parameters
  
  $result = whoami.exe -priv
  IF ($?)
  { 
    if (($result -ne $null) -and ($result -ne ""))
    {
      foreach ($priv in $result)
      {
        if ($priv.Contains("SeSecurityPrivilege"))
          { return $true }
      }
    }
  }
  return $false
}

function PromptChoice($choices, $message, $defaultChoiceNumber=0) 
{
  $choiceCollection = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
  $choices | ForEach-Object { $choiceCollection.Add([Management.Automation.Host.ChoiceDescription]$_) }
  $Host.ui.PromptForChoice("", $message, $choiceCollection, $defaultChoiceNumber)
}

function WarnIfNotRunAsAdministrator {
  if (-not (DoesCurrentUserHaveAdminPriv)) {
    $choices = "&Continue","E&xit"
    $message = "This script needs to be run as an administrator. You should exit the script and re-run as an administrator."
    $exitChoice = 1
    if ((PromptChoice $choices $message $exitChoice) -eq $exitChoice) 
    { Exit }
  }
}

function LocalUserExists  
{
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$true,HelpMessage="The user to look for")][string]$userName
  )
  $colItems = get-WmiObject -query ("select * from Win32_UserAccount where LocalAccount=True and Name='" + $userName +"'")
  ForEach ($objItem in $colItems)
  { 
    IF (-not($objItem -eq $null))
    { return $true }
  }
  return $false
}

function ADSIObjectExists([string]$objectName) 
{
  [ADSI]::Exists("WinNT://./$objectName")
}

function GroupExists 
{
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$true,HelpMessage="The group to look for")][string]$groupName
  )
  ADSIObjectExists $groupName
}

function CreateGroup 
{
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$true,HelpMessage="Name of the new group")][string]$groupName,
    [Parameter(Mandatory=$true,HelpMessage="Description of the new group")][string]$description,
    [Parameter(Mandatory=$true,HelpMessage="Domainname or Computername, indicating if a domain group or local. Current implementation only allows local groups.")][string]$domain
  )
  if ($domain -ne $env:COMPUTERNAME) 
  {
    Write-Host "Skipping creation of domain group [$domain\$groupName]" -Foregroundcolor Yellow
    return
  }
  if (-not (GroupExists $groupName)) 
  {
    $computer = [ADSI]"WinNT://."
    $group = $computer.Create("group", $groupName)
    if ($description) 
    {
      $group.InvokeSet('Description', $description)
    }
    $group.SetInfo()
    Write-Host "Domain group [$domain\$groupName] created." -Foregroundcolor Green 
  } 
  else 
  {
    Write-Host "Domain group [$domain\$groupName] already exists" -Foregroundcolor Yellow  
  }
}

function IsUserMemberOfGroup 
{
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$true,HelpMessage="The user to look for")][string]$userName,
    [Parameter(Mandatory=$true,HelpMessage="The group to query")][string]$groupName
  ) 
  $members=(net localgroup $groupName).where({$_ -match '-{79}'},'skipuntil') -notmatch '-{79}|The command completed'
  return $members -contains $userName
}

function isSvcInstalled()
{
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$true,HelpMessage="Service Name")][string]$svcName
  )
  # The service name may include a dollar-sign! (e.g. SQL Instances)
  $svcPath="hklm:\SYSTEM\CurrentControlSet\Services\" + $svcName
  IF (test-path $svcPath)  
    { return $true }
  return $false
}
