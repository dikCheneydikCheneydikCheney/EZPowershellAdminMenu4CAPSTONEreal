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
    Write-Host "4) Policy Editor"
    Write-Host "5) Baseline Information"
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
#========================Policy Editor menu=========================
function Show-PolicyEditor-Menu
{
    Clear-Host
    Write-Host "===Policy Editor==="
    Write-Host "1) Password Policy Reconfiguration"
    Write-Host "2) Net Account Monitor"
    Write-Host "b) Back to Main Menu"
}
#========================Baseline Information menu=========================

function Show-BaselineInformation-Menu
{
    Clear-Host
    Write-Host "===Baseline Information==="
    Write-Host "1) Compare Users with CSV"
    Write-Host "b) Back to Main Menu"
}

#========================Main Menu Loop=========================
do
{
    Show-Menu
    $inputOption = Read-Host "Please make a selection"
    switch($inputOption)
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
    }'4'{
        Clear-Host
        $loop = $true
        while ($loop){
        Show-PolicyEditor-Menu
        $getpolicyEditorInput = Read-Host "Please make a selection"
        switch($getpolicyEditorInput)
        {
        '1'{
            Clear-Host
            $minPasswordLength = Read-Host "Enter minimum password length"
            $minPasswordAge = Read-Host "Enter minimum password age (in days)"
            $maxPasswordAge = Read-Host "Enter maximum password age (in days)"
            $lockoutThreshold = Read-Host "Enter lockout threshold"
        
            net accounts /minpwlen:$minPasswordLength
            net accounts /minpwage:$minPasswordAge
            net accounts /maxpwage:$maxPasswordAge
            net accounts /lockoutthreshold:$lockoutThreshold
        
            Write-Host "Operation Complete"
            Pause
        }'2'{
            Clear-Host
            # Function to export security settings and parse password policy
            function Get-PasswordPolicy {
                $policyFile = "$env:TEMP\secpol.cfg"

                # Export security policies
                secedit /export /cfg $policyFile /quiet
            
                # Read the file and extract password settings
                $policy = @{}
                $content = Get-Content $policyFile
            
                foreach ($line in $content) {
                    if ($line -match "MinimumPasswordLength\s*=\s*(\d+)") { $policy["MinPasswordLength"] = $matches[1] }
                    if ($line -match "MaximumPasswordAge\s*=\s*(\d+)") { $policy["MaxPasswordAge"] = $matches[1] }
                    if ($line -match "MinimumPasswordAge\s*=\s*(\d+)") { $policy["MinPasswordAge"] = $matches[1] }
                    if ($line -match "PasswordHistorySize\s*=\s*(\d+)") { $policy["PasswordHistory"] = $matches[1] }
                    if ($line -match "LockoutBadCount\s*=\s*(\d+)") { $policy["LockoutThreshold"] = $matches[1] }
                    if ($line -match "ResetLockoutCount\s*=\s*(\d+)") { $policy["LockoutWindow"] = $matches[1] }
                    if ($line -match "LockoutDuration\s*=\s*(\d+)") { $policy["LockoutDuration"] = $matches[1] }
                }

                # Clean up the temporary file after parsing
                Remove-Item $policyFile -Force

                return $policy
            }

            # Store initial settings
            $initialPolicy = Get-PasswordPolicy

            Write-Host "Monitoring password policy changes... Press Enter to stop.`n"

            # Monitoring loop
            while ($true) {
                Start-Sleep -Seconds 5  # Check every 5 seconds
            
                # Check if user pressed Enter
                if ([console]::KeyAvailable) {
                    $key = [console]::ReadKey($true)
                    if ($key.Key -eq "Enter") {
                        break  # Exit the loop
                    }
                }
            
                # Get current policy and compare
                $currentPolicy = Get-PasswordPolicy
                $changes = @()
            
                foreach ($key in $initialPolicy.Keys) {
                    if ($initialPolicy[$key] -ne $currentPolicy[$key]) {
                        $changes += "$key changed from $($initialPolicy[$key]) to $($currentPolicy[$key])"
                    }
                }
            
                if ($changes.Count -gt 0) {
                    Write-Host "`n[ALERT] Password policy changed:`n" -ForegroundColor Red
                    $changes | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
                    Write-Host "`nUpdating reference policy..."
                    $initialPolicy = $currentPolicy  # Update reference to avoid repeated alerts
                }
            }
    
        }'b'{ $loop = $false }
        }
    }
    }'5'{
        Clear-Host
        $loop = $true
        while ($loop){
        show-BaselineInformation-Menu
        $getBaselineInformationInput = Read-Host "Please make a selection"
        switch($getBaselineInformationInput)
        {
        '1'{
            Clear-Host
            $compareCSV = Read-Host "Enter the CSV file you'd like to compare (Or create one by entering 'c')"

            if ($compareCSV -eq 'c'){
                #create CSV file
                # Get all local users
                $localUsers = Get-LocalUser
                
                # Export to CSV
                $localUsers | Export-Csv -Path "local_users.csv" -NoTypeInformation
                Write-Host "Created a file with all current local users: local_users.csv"
            }
            else{
                while ($true) {
                    try {
                        $inventoryUsers = Import-Csv -Path $compareCSV # Import the CSV as a list of users
                        break
                    }
                    catch [System.IO.FileNotFoundException] {
                        Write-Host "File Path Not Found: $CSVPath"
                    }
                    catch {
                        Write-Host "An Error Has Occurred: $_"
                    }
            
                }
                
                $systemUsers = Get-LocalUser # Get all local users on the system
            
                # Arrays to store users who are or aren't on the system
                $onSystemUsers = @()
                $notOnSystemUsers = @()
            
                # Compare each user in the inventory to the system users
                foreach ($invUser in $inventoryUsers) {
                    foreach ($sysUser in $systemUsers) {
                        if ($invUser.Name -eq $sysUser.Name) {
                            $onSystemUsers += $invUser.Name
                        }
                    }
                    
                    # If the user is not found in system, add to the not on system list
                    if ($onSystemUsers -notcontains $invUser.Name) {
                        $notOnSystemUsers += $invUser.Name
                    }
                }
            
                # Arrays to store users who are or aren't in the inventory
                $inInventoryUsers = @()
                $notInInventoryUsers = @()
            
                # Compare each system user to the inventory users
                foreach ($sysUser in $systemUsers) {
                    foreach ($invUser in $inventoryUsers) {
                        if ($sysUser.Name -eq $invUser.Name) {
                            $inInventoryUsers += $sysUser.Name
                        }
                    }
            
                    # If the system user is not in inventory, add to the not in inventory list
                    if ($inInventoryUsers -notcontains $sysUser.Name) {
                        $notInInventoryUsers += $sysUser.Name
                    }
                }
            
                # Output the results
                Write-Host "`nUsers Not on the System:"
                Write-Host $notOnSystemUsers -ForegroundColor Red
                Write-Host "`nUsers Not in the Inventory:"
                Write-Host $notInInventoryUsers -ForegroundColor Red
            }
            Pause
        }'b'{ $loop = $false }
        }
    }
    }'6'{

    }'7'{

    }'Q'{
    return
    }
    }
}
until ($input -eq 'q')
