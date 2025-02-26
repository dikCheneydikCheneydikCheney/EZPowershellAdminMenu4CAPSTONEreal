#TODO
#Finish Menu for account creation, removal, information, and modification
#Create Menu for viewing inbound, outbound, and all connections (netstat stuff)
#Brainstorm more ideas for PS Admin menu
#==========================Powershell main menu====================================
function Show-Menu
{
    param(
    [string]$Title = 'Powershell EZ Admin Menu'
    )
    Clear-Host
    Write-Host "===$Title==="

    Write-Host "1) File Hashes"
    Write-Host "2) Get, Kill, Start Processes"
    Write-Host "3) Account Creation, Removal, Information, Modifications"
    Write-Host "4) WIP Option"
    Write-Host "5) WIP Option"
    Write-Host "6) WIP Option"
    Write-Host "7) WIP Option"
    Write-Host "Quit (q)"

}
#=========================filehash sub menu=======================================
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
#======================get, kill, and start processes menu and submenu=============================
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
#============================Account Creation, Removal, information, and modification Menus and sub menus==========================================
function show-AccountOptions-Menu
{
    Clear-Host
    Write-Host "===Account Creation, Removal, Information, Modification Menu==="
    Write-Host "1) Account Creation"
    Write-Host "2) Account Removal"
    Write-Host "3) Account Information"
    Write-Host "4) Account Modification"
    Write-Host "b) Back To Main Menu"
}
#========================Local Account information menu=========================
function show-LocalAccountInformation-Menu
{
    Clear-Host
    Write-Host "===Account Information==="
    Write-Host "1) Get All Local Accounts"
    Write-Host "2) Get Specific User Account"
    Write-Host "3) Get User SID"
    Write-Host "4) Get User account via SID"
    Write-Host "b) Back to Account Creation, Removal, Information, Modification Menu"
}
do
{
    Show-Menu
    $input = Read-Host "Please make a selection"
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
            $loopGetProcesses = $true
            While ($loopGetProcesses){
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
            
                }'b'{ $loopGetProcesses = $false }
                }
            }
        }'2'{
            Clear-Host
            $loopKillProcessesMenu = $true
            While ($loopKillProcessesMenu){
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

                }'b'{ $loopKillProcessesMenu = $false }         
                }
            }
        
        }'3'{
            Clear-Host
            $loopStartProcesses = $true
            While ($loopStartProcesses){
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
            

            }'b'{ $loopStartProcesses = $false }  
            }
            }

        }'b'{ $loop = $false } 
        }
    }  

    }'3'{
        Clear-Host
        $loop = $true
        While ($loop){
        show-AccountOptions-Menu
        $getAccountOptions = Read-Host "Please make a selection"
        switch($getAccountOptions)
        {
        '1'{
            #account creation
            Clear-Host
            $creationUsername = Read-Host "Input the desired Username"
            $creationPassword = Read-Host -AsSecureString "Input Desired Password"
            $creationFullName = Read-Host "Input the Full Name of the User"
            $creationDescription = Read-Host "Input the description of the account"
            $creationGroup = Read-Host "Input Desired Group for user to join (If you don't know which Groups are available, use 'Users' as default)"
            New-LocalUser -Name $creationUsername -Description $creationDescription -FullName $creationFullName -Password $creationPassword
            Add-LocalGroupMember -Group $creationGroup -Member $creationUsername
            # !!Fix bug where it prints user once menu is closed
        }'2'{
            #account removal via username, possibly do SID in future & list deletion?
            Clear-Host
            $deletionUsername = Read-Host "Input the Username of the account you'd like to delete"
            Remove-LocalUser -Name $deletionUsername -Confirm
            Pause
        }'3'{
            #account information
            #create submenu for this
            Clear-Host
            $loopAccountInformation = $true
            While ($loopAccountInformation){
            show-LocalAccountInformation-Menu
            $selectLocalAccountInformation = Read-Host "Please make a selection"
            switch($selectLocalAccountInformation)
            {
            '1'{
                #fix issue where list appears after a different command is ran
                Clear-Host
                Get-LocalUser
                pause
            }'2'{
                #fix issue where list appears after a different command is ran
                Clear-Host
                $getSpecificUser = Read-Host "Input the User you're trying to find"
                Get-LocalUser -Name $getSpecificUser
                pause
            }'3'{
                #fix issue where list appears after a different command is ran
                Clear-Host
                $getSpecificUserSID = Read-Host "Input the User you're trying to get the SID from"
                Get-LocalUser -Name $getSpecificUserSID | Select-Object sid
                pause
            }'4'{
                #implement getting user account by inputing SID

            }'b'{ $loopAccountInformation = $false }
            }
        }
        }'4'{
            #account modification
            #create submenu for this
            Clear-Host
            Write-Host "test1"
            Pause
        
        










        }'b'{ $loop = $false } 
        }
    }

    #add more menu options, brainstorm MF!
    }'4'{

    }'5'{

    }'6'{

    }'7'{

    }'Q'{
    return
    }
    }
}
until ($input -eq 'q')
