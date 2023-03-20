# Run this script as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    exit
}

# Import the ActiveDirectory module if not already loaded
if (-not (Get-Module -Name 'ActiveDirectory')) {
    Import-Module ActiveDirectory
}

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

# Set the number of additional users to create
$numberOfUsers = X

# Set the password for all users
$password = ConvertTo-SecureString "Zubur1!" -AsPlainText -Force

# Set the target OU for user creation
$targetOU = "OU=Users,DC=yourdomain,DC=com" # Replace 'yourdomain' and 'com' with your domain information

# Create additional users
for ($i = $highestUserNumber + 1; $i -le $highestUserNumber + $numberOfUsers; $i++) {
    $userName = "user$i"
    $userPrincipalName = "$userName@yourdomain.com" # Replace 'yourdomain.com' with your domain information

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
        $userPrincipalName = "$userName@yourdomain.com" # Replace 'yourdomain.com' with your domain information

        # Generate a logon event (Event ID 4624) for each user
        $credential = New-Object System.Management.Automation.PSCredential -ArgumentList @($userPrincipalName, $password)
        $secPassword = $credential.Password
        $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPassword))

        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"& {Start-Sleep -Seconds 1; Exit}`"" -Credential $credential -WindowStyle Hidden
    }

    Write-Output "Successfully generated Logon events (ID 4624) for all the users."
