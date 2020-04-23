# -----------------------------------------------------------------------------------------
# Classification: UNCLASSIFIED
# Name: FullScreenPause.ps1
# Purpose: Pause and INFORM the user of something...
# Version: 1.0 - Mar 2017
# -----------------------------------------------------------------------------------------
param ([string]$text)

Add-Type -AssemblyName System.Windows.Forms;

[System.Windows.Forms.Application]::EnableVisualStyles()

[System.Windows.Forms.MessageBox]::Show(
    "$text","Press any key...", 
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information);