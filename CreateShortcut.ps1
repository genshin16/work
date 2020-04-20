# ---------------------------------------------------------------------------------------
# Name: CreateShortcut.ps1
# Purpose: Script for making windows shortcuts (lnk files)
# Reference:
#   http://www.leedesmond.com/weblog/?p=60
#   http://msdn.microsoft.com/en-us/library/xsy6k3ys(v=vs.84).aspx
# Version: 1.0 - Sept 2019
# ---------------------------------------------------------------------------------------
# New-Shortcut -name "$home\Desktop\myhome.lnk" -target "someFile.exe" -argms "filename.ext" 
#              -workDir "C:\temp" -Desc "This is my home folder" -MyIcon "someFile.ico"

function New-Shortcut
{
  param([string]$name, [string]$target, [string]$argms, [string]$workDir, [string]$Desc, [string]$MyIcon)
  
  IF ($name -eq $null) 
  {
    Write-Host "$name cannot be null"
    Exit
  }
  IF ($target -eq $null)
  {
    Write-Host "$target cannot be null"
    Exit
  }
  
  $wshshell = New-Object -Com "WScript.Shell"
  $lnk = $wshshell.CreateShortcut($name)    # Where the shortcut lives. (Must have an extension of .lnk or .url)
  $lnk.TargetPath = $target                 # the target of the shorcut
  
  IF (($argms -ne $null) -and ($argms -ne ""))
  {
    $lnk.Arguments = $argms                  # appends the arguments to the $lnk.TargetPath property
  }
  IF (($workDir -ne $null) -and ($workDir -ne ""))
  {
    $lnk.WorkingDirectory = $workDir        # maps to Start in: on GUI
  }
  IF (($Desc -ne $null) -and ($Desc -ne ""))
  {
    $lnk.Description = $Desc                # corresponds to the Comment field on the shortcut tab.
  }
  IF (($MyIcon -ne $null) -and ($MyIcon -ne ""))
  {
    $lnk.IconLocation = $MyIcon                
  }
  
  try
  {
    $lnk.Save()
    Write-Host "Shortcut created" -ForegroundColor Green
  }
  catch [system.exception]
  {
    Write-Host "Failed to save shortcut" -ForegroundColor Yellow
    #Write-Error $("CAUGHT: " + $_.Exception.InnerException.GetType().FullName);
    #Write-Error $("CAUGHT: " + $_.Exception.InnerException.Message);
  }
} # end New-Shortcut
