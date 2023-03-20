# Run this script as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    exit
}

# Import the ActiveDirectory module if not already loaded
if (-not (Get-Module -Name 'ActiveDirectory')) {
    Import-Module ActiveDirectory
}

# Set the number of users to create
$numberOfUsers = X

# Set the password for all users
$password = ConvertTo-SecureString "Zubur1!" -AsPlainText -Force

# Set the target OU for user creation
$targetOU = "OU=Users,DC=yourdomain,DC=com" # Replace 'yourdomain' and 'com' with your domain information

# Create users
for ($i = 1; $i -le $numberOfUsers; $i++) {
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

Write-Output "Successfully created $numberOfUsers users with the naming format user1 up to user$numberOfUsers."

$proceed = Read-Host "Do you want to generate Logon events (ID 4624) for the created users? (yes/no)"
if ($proceed -eq "yes") {
    for ($i = 1; $i -le $numberOfUsers; $i++) {
        $userName = "user$i"
        $userPrincipalName = "$userName@yourdomain.com" # Replace 'yourdomain.com' with your domain information

        # Run this command on the local computer to simulate a logon event (Event ID 4624) for each user
        $command = @"
$logonSuccess = @"
        [System.Diagnostics.Eventing.Reader.EventLogRecord]@{
            Id=4624;
            LogName='Security';
            MachineName='$env:COMPUTERNAME';
            TimeCreated=[datetime]::Now;
            UserId=[System.Security.Principal.SecurityIdentifier]::new('S-1-5-21-1234567890-1234567890-1234567890-1001');
            Properties=@(
                [System.Diagnostics.Eventing.Reader.EventProperty]@{Value='$userName'};
                [System.Diagnostics.Eventing.Reader.EventProperty]@{Value='$userPrincipalName'};
            );
        "@

Add-Type -TypeDefinition $logonSuccess -Language CSharp

[void][System.Diagnostics.Eventing.Reader.EventLogRecord]::new()
"@
        Invoke-Expression -Command $command
    }

    Write-Output "Successfully generated Logon events (ID 4624) for the created users."
}
