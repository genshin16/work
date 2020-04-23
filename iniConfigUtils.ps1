# -----------------------------------------------------------------------------------------
# Name: iniConfigUtils.ps1
# Purpose: .ini Config Utils and Transcript Log Utils
# Version: 1.0 - Oct 2019
# -----------------------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# The following routine was snagged from the "Hey, Scripting Guy! Blog".
# It reads any reasonably-formatted .ini file into a specially-formatted hash file.
# -----------------------------------------------------------------------------
Function Get-IniContent 
{ 
    <# 
    .Synopsis
        Gets the content of an INI file 
         
    .Description
        Gets the content of an INI file and returns it as a hashtable 
         
    .Notes
        Author    : Oliver Lipkau <oliver@lipkau.net> 
        Blog      : http://oliver.lipkau.net/blog/ 
        Date      : 2010/03/12 
        Version   : 1.0 
         
        #Requires -Version 2.0 
         
    .Inputs
        System.String 
         
    .Outputs
        System.Collections.Hashtable 
         
    .Parameter FilePath 
        Specifies the path to the input file. 
         
    .Example
        $FileContent = Get-IniContent "C:\myinifile.ini" 
        ----------- 
        Description 
        Saves the content of the c:\myinifile.ini in a hashtable called $FileContent 
     
    .Example
        $inifilepath | $FileContent = Get-IniContent 
        ----------- 
        Description 
        Gets the content of the ini file passed through the pipe into a hashtable called $FileContent 
     
    .Example
        C:\PS>$FileContent = Get-IniContent "c:\settings.ini" 
        C:\PS>$FileContent["Section"]["Key"] 
        ----------- 
        Description 
        Returns the key "Key" of the section "Section" from the C:\settings.ini file 
         
    .Link
        http://gallery.technet.microsoft.com/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91
    #> 
     
    # [CmdletBinding()] 
    Param( 
        [ValidateNotNullOrEmpty()] 
        [ValidateScript({(Test-Path $_) -and ((Get-Item $_).Extension -eq ".ini")})] 
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)] 
        [string]$FilePath 
    ) 
     
    Begin 
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"} 
         
    Process 
    { 
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath" 
             
        $ini = @{} 
        switch -regex -file $FilePath 
        { 
            "^\[(.+)\]$" # Section 
            { 
                $section = $matches[1] 
                $section = $section.trimEnd(" ") # added
                $ini[$section] = @{} 
                $CommentCount = 0 
            } 
            "^(;.*)$" # Comment 
            { 
                if (!($section)) 
                { 
                    $section = "No-Section" 
                    $ini[$section] = @{} 
                } 
                $value = $matches[1] 
                $CommentCount = $CommentCount + 1 
                $name = "Comment" + $CommentCount 
                $ini[$section][$name] = $value 
            }  
            "(.+?)=(.*)" # Key 
            { 
                if (!($section)) 
                { 
                    $section = "No-Section" 
                    $ini[$section] = @{} 
                } 
                $name,$value = $matches[1..2] 
                $name = $name.trimEnd(" ") # added
                $section = $section.trimEnd(" ") # added
                $ini[$section][$name] = $value 
            } 
        } 
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FilePath" 
        Return $ini 
    } 
         
    End 
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"} 
}

# ---------------------------------------------------------------------------
#  This function will read data from a config file.
#  It makes the following assumptions:
#   - Config file is called Security.ini
#   - Config file Section Header = [Security]
#   - Config file is located inside of the Scripts directory
#   - The contents of the config file look (grossly) like this:
#         [Security]
#         year=2013
#         quarter=Q3
#         buildDate=0622
#         logDir=C:\users\All Users\Security
# ---------------------------------------------------------------------------
function get-configured-item([string]$itemName, [string]$pathToScriptsDir = '.')
{
   $hash = Get-IniContent ( $pathToScriptsDir + '\Security.ini')
   return $hash['Security'][$itemName]
}

function getTranscriptFileExtraAddedToFileName()
{
    return ".txt"
}

# creates/starts a transcript file
#
# returns full transcript filename
#
function startTranscriptLogFile( [string]$coreName , [string]$pathToScriptsDir = '.')
{
    # build logging variables
    $baseName = "$coreName.log"

    # get configured values
    $the_quarter =    get-configured-item 'quarter'   $pathToScriptsDir
    $the_year =       get-configured-item 'year'      $pathToScriptsDir
    #$the_build_date = get-configured-item 'buildDate' $pathToScriptsDir
    $the_log_dir=     get-configured-item 'logDir'    $pathToScriptsDir

    $transcriptFile=($the_log_dir + '\' + $the_year + '_' + $the_quarter + '_' + $baseName)

    # there is bug in start-transcript -append in that it appends in UTF-16.
    # So, write out a TEMP transcript to append to the "real" one at the end
    $added = getTranscriptFileExtraAddedToFileName
    $transcriptFile = ( $transcriptFile + $added )

    # mkdir (as needed)
    #
    # check if base log dir exists
    IF (-not(Test-Path -PathType Container $the_log_dir))
    {
        Write-Host "Creating log directory`n" 
        $null = mkdir $the_log_dir
    }

    IF ($Host.Name -eq "Windows PowerShell ISE Host")
    {
        Write-Host "Script running in debugger`n" -ForegroundColor Yellow
    }
    else
    {
        # a "transcript" copies everthing sent to the console to a file.
        # well, almost everything  http://connect.microsoft.com/PowerShell/feedback/details/315875
        $null = start-transcript -path $transcriptFile -Force

        # say howdy
        write-host "$(Get-Date -f o) Starting ...`n" 
    }

    return $transcriptFile
}

# ends/completes a transcript file
#
function endTranscriptLogFile( [string]$file )
{
    IF ($Host.Name -ne "Windows PowerShell ISE Host")
    { 
        # wave good-bye
        write-host "$(Get-Date -f o) Ending ...`n" 

        # block the message indicating transcript log location
        $null = stop-transcript 
        ( Start-Sleep -milliseconds 500 )
    
        # There are 2 files:
        #    - The permanent file
        #    - The "temp file"/session file/transcript file
        #
        # we have to "massage" this temp file and then APPEND it to the REAL/PERMANENT file
        #
        # we are doing these extra steps because the transcript file often ends up in UTF16
        # and the only way to force 8 bit chars is to use add-content
        #
        $the_extra = getTranscriptFileExtraAddedToFileName
        $permanent_fname = $file.replace( $the_extra,"")

        # get the current contents, fix the EOL and then append to the "real" file
        (Get-Content $file) | Foreach-Object {$_ -replace "`r", "`n"} | Add-Content -Path $permanent_fname -Encoding ASCII -Force
    
        # remote the temp file
        ( Start-Sleep -milliseconds 100 )
        remove-item $file
        
        # fake the message that would have documented the SESSION and not the permanent log file
        # write-host "Transcript stopped, output file is $permanent_fname"
    }
}

