# ---------------------------------------------------------------------------------------
# Name: profile.ps1
# Purpose: Script for setting powershell background colors and window titles
#
# Note: This is **NOT** a STIG requirement!!
#       It's more of a best-practice as it provides SA as to the mode of the 
#       current shell (dangerous vs. safe).
# Version: 1.0 - June 2019
# ---------------------------------------------------------------------------------------
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($user)
$proc=[diagnostics.process]::GetCurrentProcess()   
$isAdmin=$principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$prefix=""

IF ($isAdmin)
{ $prefix="ADMIN: " }
ELSE
{ $prefix="LIMITED_USER: " }
    
switch ( $Host.Name )
{
  "Windows PowerShell ISE Host"
  {
    $Color_Label = "DarkCyan"
    $Color_Value_1 = "Magenta"
    $Color_Value_2 = "DarkGreen"
    $HostWidth = 80
    IF ($isAdmin)
      {$psISE.Options.CommandPaneBackgroundColor ="Salmon" }
    ELSE
      {$psISE.Options.CommandPaneBackgroundColor ="LightBlue" }    
  }
  default #"PowerShellPlus Host"
  {
    # Identify if user is an admin or not
    IF ($isAdmin)
    { $Host.UI.RawUI.Backgroundcolor="DarkRed" }
    ELSE
    { $Host.UI.RawUI.Backgroundcolor="DarkBlue" }
  }
}

# Don't try to update Configuration Manager (CM)
#Set-CMCmdletUpdateCheck -CurrentUser -IsUpdateCheckEnabled $False
 
# Identify if powershell is 32bit or 64bit build 
IF ($proc.path -match '\\syswow64\\') 
  { $prefix=$prefix+"{32 bit} " }    
ELSE 
  { $prefix=$prefix+"{64 bit} " }

# color powershell errors yellow, instead of the scary red on black.
$colors=$Host.PrivateData
$colors.ErrorForegroundColor = "yellow"

$Host.UI.RawUI.WindowTitle = $prefix + $Host.UI.RawUI.WindowTitle
clear-host