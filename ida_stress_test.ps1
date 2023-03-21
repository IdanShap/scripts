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
New-ADOrganizationalUnit -Name "Stress Test" -Path $domainPath

$targetOU = "OU=Stress Test,$domainPath"

# Create additional users
for ($i = $highestUserNumber + 1; $i -le $highestUserNumber + $numberOfUsers; $i++) {
    $userName = "user$i"
    $userPrincipalName = "$userName@$domainName"

    New-ADUser -Name $userName `
        -SamAccountName $userName `
        -UserPrincipalName $userPrincipalName `
        -AccountPassword $password `
        -Enabled $true `
        -Path $targetOU `
        -ChangePasswordAtLogon $false `
        -PasswordNeverExpires $true
}

Write-Output "Successfully created $numberOfUsers additional users with the naming format user$($highestUserNumber + 1) up to user$($highestUserNumber + $numberOfUsers)."

$proceed = Read-Host "Do you want to generate Logon events (ID 4624) for all the users? (yes/no)"
if ($proceed -eq "yes") {
    # Get all user accounts
    $allUsers = Get-ADUser -Filter "SamAccountName -like 'user*'" -Properties SamAccountName | Select-Object -ExpandProperty SamAccountName

        foreach ($userName in $allUsers) {
        $userPrincipalName = "$userName@$domainName" 

        # Generate a logon event (Event ID 4624) for each user
        $credential = New-Object System.Management.Automation.PSCredential -ArgumentList @($userPrincipalName, $password)
        $secPassword = $credential.Password
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPassword))

        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"& {Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 5); net use * /delete /y > $null; net use \\\\$env:COMPUTERNAME\\c$ /user:$userPrincipalName '$plainPassword'; net use * /delete /y > $null;}`""
    }

    Write-Output "Successfully generated Logon events (ID 4624) for all the users."
}

