# Capture error messages in a log file
$ErrorActionPreference = "Continue"
$ErrorLog = "error_log.txt"


# Run this script as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    exit
}

# Import the ActiveDirectory module if not already loaded
if (-not (Get-Module -Name 'ActiveDirectory')) {
    Import-Module ActiveDirectory
}

# Prompt for domain name
$domainName = Read-Host "Please enter your domain name (e.g., yourdomain.com)"
$domainPath = "DC=" + ($domainName -replace '\.', ',DC=')

# Determine the highest existing user number
$existingUsers = Get-ADUser -Filter "SamAccountName -like 'user*'" -Properties SamAccountName | Select-Object -ExpandProperty SamAccountName
$highestUserNumber = 0
foreach ($user in $existingUsers) {
    if ($user -match 'user(\d+)') {
        $userNumber = [int]$matches[1]
        if ($userNumber -gt $highestUserNumber) {
            $highestUserNumber = $userNumber
        }
    }
}

# Prompt for the number of additional users to create
$numberOfUsers = Read-Host "Enter the number of users you want to create"

# Set the password for all users
$password = ConvertTo-SecureString "Zubur1!" -AsPlainText -Force

# Create the Stress Test OU
New-ADOrganizationalUnit -Name "Stress Test" -Path $domainPath -ProtectedFromAccidentalDeletion $false

$targetOU = "OU=Stress Test,$domainPath"

# Create a dedicated group for accessing administrative shares
New-ADGroup -Name "StressTestAdmins" -GroupScope Global -Path $targetOU -Description "Group for Stress Test users with access to administrative shares"

# Create additional users
Write-Output "Generating the users - please wait"
for ($i = $highestUserNumber + 1; $i -le $highestUserNumber + $numberOfUsers; $i++) {
    $userName = "user$i"
    $userPrincipalName = "$userName@$domainName"
	
	# Set the user's home directory and profile path for Remote Desktop
    $homeDirectory = "\\$domainName\users\home\$userName"
    $profilePath = "\\$domainName\users\profiles\$userName"

    $newUser = New-ADUser -Name $userName `
        -SamAccountName $userName `
        -UserPrincipalName $userPrincipalName `
        -AccountPassword $password `
        -Enabled $true `
        -Path $targetOU `
        -ChangePasswordAtLogon $false `
        -PasswordNeverExpires $true `
        -CannotChangePassword $true `
		-ProfilePath "\DC1\c$\profiles\$userName" `
		-HomeDrive "H" `
		-HomeDirectory "\DC1\c$\home\$userName"`
        -PassThru

    # Add the user to the "StressTestAdmins" group
    Add-ADGroupMember -Identity "StressTestAdmins" -Members $newUser
	Add-ADGroupMember -Identity "Remote Desktop Users" -Members $newUser
	
	
	#for debug purpose:
	echo "username " + $userName
	echo "UPN " + $userPrincipalName
	echo "pass " + $password
}

# Add "StressTestAdmins" group to the "Remote Management Users" local group
Add-ADGroupMember -Identity "Remote Management Users" -Members "StressTestAdmins"


Write-Output "Successfully created $numberOfUsers additional users with the naming format user$($highestUserNumber + 1) up to user$($highestUserNumber + $numberOfUsers)."

# Grant "StressTestAdmins" group access to the C:\ drive administrative share
Write-Output "granting the StressTestAdmins group access to the C:\ drive administrative share - please wait, may take up to few minutes"
$folderPath = "C:\"
$acl = Get-Acl $folderPath
$groupIdentity = "$domainName\StressTestAdmins"
$permission = New-Object System.Security.AccessControl.FileSystemAccessRule($groupIdentity, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")
$acl.AddAccessRule($permission)
Set-Acl -Path $folderPath -AclObject $acl

Write-Output "Successfully granted the StressTestAdmins group access to the C:\ drive administrative share."

# Update the LocalAccountTokenFilterPolicy registry setting to allow remote UAC for local accounts
Write-Output "Updating the LocalAccountTokenFilterPolicy registry setting..."
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$regName = "LocalAccountTokenFilterPolicy"
$regValue = 1
New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWORD -Force | Out-Null

Write-Output "Successfully updated the LocalAccountTokenFilterPolicy registry setting."

# Disable the Windows Firewall
Write-Output "Disabling the Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
Write-Output "Successfully disabled the Windows Firewall."

$proceed = Read-Host "Do you want to generate Logon events (ID 4624) for all the users? (yes/no)"
if ($proceed -eq "yes") {
    # Get all user accounts
    $allUsers = Get-ADUser -Filter "SamAccountName -like 'user*'" -Properties SamAccountName | Select-Object -ExpandProperty SamAccountName
	
	# get plain password
	$plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

    foreach ($userName in $allUsers) {
        $userPrincipalName = "$userName@$domainName"

        # Generate a logon event (Event ID 4624) for each user
        $credential = New-Object System.Management.Automation.PSCredential -ArgumentList @($userName, $password)

        $scriptBlock = {
            param($envComputerName, $userName, $userPrincipalName, $password)

            # Sleep for a random number of seconds
            Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 5)

            # Access the network share
            try {
                $netUseResult = net use * /delete /y
                $netUseResult = net use \\$envComputerName\c$ /user:`'$userName`' `'$password`'
                $netUseResult = net use * /delete /y
            } catch {
                Write-Error "Failed to access the network share for user ${userName}: $_"
            }
        }

        Invoke-Command -ComputerName $env:COMPUTERNAME -ScriptBlock $scriptBlock -ArgumentList $env:COMPUTERNAME, $userName, $userPrincipalName, $password -Credential $credential
    }

    Write-Output "Successfully generated Logon events (ID 4624) for all the users."
}


if ($proceed -eq "yes") {   
    Write-Output "Successfully generated Logon events (ID 4624) for all the users."
}

# Prompt to delete the users and the OU
$deleteAll = Read-Host "Do you want to delete all the created users and the Stress Test OU? (yes/no)"
if ($deleteAll -eq "yes") {
	# Delete all users within the "Stress Test" OU
	Write-Output "Deleting all users within the Stress Test OU..."
	Get-ADUser -Filter * -SearchBase $targetOU | Remove-ADUser -Confirm:$false
	Write-Output "Successfully deleted all users within the Stress Test OU."

	# Remove "StressTestAdmins" group from the "Remote Management Users" local group
	Remove-ADGroupMember -Identity "Remote Management Users" -Members "StressTestAdmins" -Confirm:$false
	

	# Delete the "StressTestAdmins" group
	Write-Output "Deleting the StressTestAdmins group..."
	Get-ADGroup -Filter {Name -eq 'StressTestAdmins'} | Remove-ADGroup -Confirm:$false
	Write-Output "Successfully deleted the StressTestAdmins group."

	# Delete the "Stress Test" OU
	Remove-ADOrganizationalUnit -Identity $targetOU -Confirm:$false
	Write-Output "Successfully deleted the Stress Test OU."
}
# Revert the LocalAccountTokenFilterPolicy registry setting
Write-Output "Reverting the LocalAccountTokenFilterPolicy registry setting..."
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$regName = "LocalAccountTokenFilterPolicy"
$regValue = 0
Set-ItemProperty -Path $regPath -Name $regName -Value $regValue

Write-Output "Successfully reverted the LocalAccountTokenFilterPolicy registry setting."

# Revert "StressTestAdmins" group access to the C:\ drive administrative share
Write-Output "Revoking the StressTestAdmins group access to the C:\ drive administrative share..."
$folderPath = "C:\"
$acl = Get-Acl $folderPath
$groupIdentity = "$domainName\StressTestAdmins"
$accessRule = $acl.Access | Where-Object { $_.IdentityReference -eq $groupIdentity }
if ($accessRule) {
    $acl.RemoveAccessRule($accessRule) | Out-Null
    Set-Acl -Path $folderPath -AclObject $acl
}

Write-Output "Successfully revoked the StressTestAdmins group access to the C:\ drive administrative share."

# Prompt to re-enable the Windows Firewall
$enableFirewall = Read-Host "Do you want to re-enable the Windows Firewall? (yes/no)"
if ($enableFirewall -eq "yes") {
    Write-Output "Re-enabling the Windows Firewall..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Output "Successfully re-enabled the Windows Firewall."
} else {
    Write-Output "Windows Firewall remains disabled. Please remember to enable it manually later."
}
