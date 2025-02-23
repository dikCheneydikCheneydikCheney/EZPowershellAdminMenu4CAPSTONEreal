#TODO
#Begin Menu for account creation, removal, information, and modification 
#Brainstorm more ideas for PS Admin menu

function Show-Menu
{
    param(
    [string]$Title = 'Powershell EZ Admin Menu'
    )
    Clear-Host
    Write-Host "===$Title==="

    Write-Host "1: File Hashes"
    Write-Host "2: Get, Kill, Start Processes"
    Write-Host "Option 3"
    Write-Host "Quit (q)"

}

function Show-FileHash-Menu
{

    Clear-Host
    Write-Host "===File Hash Menu==="
    Write-Host "1: View SHA1"
    Write-Host "2: View SHA256"
    Write-Host "3: View SHA384"
    Write-Host "4: View SHA512"
    Write-Host "5: View MD5"
    Write-Host "6: View RIPEMD160"
    Write-Host "7: View MACTripleDES"
    Write-Host "Back To Main Menu (b)"
}

function Show-getKillStartProcesses-Menu
{
    Clear-Host
    Write-Host "===Get, Kill, Start Processes==="
    Write-Host "1: Get Processes"
    Write-Host "2: Kill Processes"
    Write-Host "3: Start Processes"
    Write-Host "Back to Main Menu (b)"
}

function Show-getProcesses-Menu
{
    Clear-Host
    Write-Host "===Get Process Menu==="
    Write-Host "1: Get All Processes"
    Write-Host "2: Get Process Filepath"
    Write-Host "3: Get Process Username (!!!MUST BE ADMIN!!!)"
    Write-Host "4: Get Process Via PID"
    Write-Host "Back to Main Menu (b)"
}

function Show-killProcesses-Menu
{
    Clear-Host
    Write-Host "===Kill Processes Menu==="
    Write-Host "1: Stop Process By Name"
    Write-Host "2: Stop Process By PID"
    Write-Host "3: Stop Process not owned by current user (!!!MUST BE ADMIN!!!)"
    Write-Host "Back to Main Menu (b)"
    
}

function show-startProcesses-Menu
{
    Clear-Host
    Write-Host "===Start Processes Menu==="
    Write-Host "1: Start Process Via File Name"
    Write-Host "2: Start Process As Administrator"
    Write-Host "Back to Main Menu (b)"
}
do
{
    Show-Menu
    $input = Read-Host "please make a selection"
    switch($input)
    {
    '1' {
        Clear-Host
        $loop = $true
        While ($loop){
            Show-FileHash-Menu
            $fileHashInput = Read-Host "Please make a selection"
            switch($fileHashInput)
            {
            '1' {
                Clear-Host
                $sha1FP = Read-Host "Enter Filepath to file (EX: C:\FilePath\FP\File.example)"
                Get-FileHash $sha1FP -Algorithm SHA1 | Format-List
                Pause

            }'2'{
                Clear-Host
                $sha256FP = Read-Host "Enter Filepath to file (EX: C:\FilePath\FP\File.example)"
                Get-FileHash $sha256FP -Algorithm SHA256 | Format-List
                Pause

            }'3'{
                Clear-Host
                $sha384FP = Read-Host "Enter Filepath to file (EX: C:\FilePath\FP\File.example)"
                Get-FileHash $sha384FP -Algorithm SHA384 | Format-List
                Pause

            }'4'{
                Clear-Host
                $sha512FP = Read-Host "Enter Filepath to file (EX: C:\FilePath\FP\File.example)"
                Get-FileHash $sha512FP -Algorithm SHA512 | Format-List
                Pause

            }'5'{
                Clear-Host
                $md5FP = Read-Host "Enter Filepath to file (EX: C:\FilePath\FP\File.example)"
                Get-FileHash $md5FP -Algorithm MD5 | Format-List
                Pause

            }'6'{
                Clear-Host
                $ripemd160FP = Read-Host "Enter Filepath to file (EX: C:\FilePath\FP\File.example)"
                Get-FileHash $ripemd160FP -Algorithm RIPEMD160 | Format-List
                Pause

            }'7'{
                Clear-Host
                $macTripleDESFP = Read-Host "Enter Filepath to file (EX: C:\FilePath\FP\File.example)"
                Get-FileHash $macTripleDESFP -Algorithm MACTripleDES | Format-List
                Pause

            }'b'{ $loop = $false }
        }
    }

    }'2'{
        Clear-Host
        $loop = $true
        While ($loop){
        Show-getKillStartProcesses-Menu
        $getKillStartInput = Read-Host "Please make a selection"
        switch($getKillStartInput)
        {
        '1' {
            Clear-Host
            $loop = $true
            While ($loop){
            Show-getProcesses-Menu
            $getProcessInput = Read-Host "Please make a selection"
            switch($getProcessInput)
            {
            '1'{
                Get-Process
                Pause

            }'2'{
                Clear-Host
                $enterFileName = Read-Host "Enter File Name"
                Get-Process $enterFileName -FileVersionInfo
                Pause

            }'3'{
                Clear-Host
                $enterFileName2 = Read-Host "Enter File Name"
                Get-Process $enterFileName2 -IncludeUserName
                Pause

            }'4'{
                Clear-Host
                $getEnterPID = Read-Host "Enter PID number"
                Get-Process -Id $getEnterPID 
                Pause
            
                }'b'{ $loop = $false }
                }
            }
        }'2'{
            Clear-Host
            $loop = $true
            While ($loop){
            Show-KillProcesses-Menu
            $killProcessesInput = Read-Host "Please make a selection"
            switch($killProcessesInput)
            {
            '1'{
                Clear-Host
                $stopProcessName = Read-Host "Enter the program name you'd like to stop"
                Stop-Process -Name $stopProcessName
                Pause

            }'2'{
                Clear-Host
                $stopProcessID = Read-Host "Enter the program PID you'd like to stop"
                Stop-Process -Id $stopProcessID -Confirm -PassThru
                Pause

            }'3'{
                Clear-Host
                $stopOtherUserProcess = Read-Host "Get Process name being ran by other user"
                Get-Process -Name $stopOtherUserProcess | Stop-Process
                Pause

                }'b'{ $loop = $false }         
                }
            }
        
        }'3'{
            Clear-Host
            $loop = $true
            While ($loop){
            show-startProcesses-Menu
            $startProcessesInput = Read-Host "Please make a selection"
            switch($startProcessesInput)
            {
            '1'{
                Clear-Host
                $enterStartFileExec = Read-Host "Please enter the file name and extention, (EX: example.exe)"
                Start-Process $enterStartFileExec
                Pause

            }'2'{
                Clear-Host
                $enterStartFileExecAdmin = Read-Host "Pleas enter the file name you'd like to run as admin, (EX: example.exe)"
                Start-Process $enterStartFileExecAdmin -Verb RunAs
            

            }'b'{ $loop = $false }  
            }
            }

        }'b'{ $loop = $false } 
        }
    }  

    }'3'{
        Clear-Host
        'You Chose option #3'




    }'Q'{
    return
    }
    }
}
until ($input -eq 'q')
