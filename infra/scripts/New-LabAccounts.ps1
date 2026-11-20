<#
.SYNOPSIS
    Create the single non-admin lab identity used by the scenario.
.DESCRIPTION
    Creates C0015\duc.user, adds it to Remote Desktop Users on the workstation and sets the password.
    The domain Administrator already exists; the maintenance task is created separately with
    attack-playbook/setup/create-maintenance-task.ps1.
.EXAMPLE
    .\New-LabAccounts.ps1 -DomainController DC01 -Workstation WS01
#>
param(
    [string]$DomainController = 'DC01',
    [string]$Workstation = 'WS01',
    [string]$User = 'duc.user',
    [securestring]$Password
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$existing = Get-ADUser -Filter "SamAccountName -eq '$User'" -Server $DomainController -ErrorAction SilentlyContinue
if (-not $existing) {
    if (-not $Password) { $Password = Read-Host -AsSecureString "Password for $User" }
    New-ADUser -SamAccountName $User -Name 'Duc User' -DisplayName 'Duc User' `
        -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true `
        -Server $DomainController
    Write-Host "[+] created $User"
} else {
    Write-Host "[=] $User exists"
}

Invoke-Command -ComputerName $Workstation -ScriptBlock {
    param($u)
    $group = [ADSI]"WinNT://$env:COMPUTERNAME/Remote Desktop Users,group"
    try { $group.Add("WinNT://$env:USERDOMAIN/$u") ; Write-Host "[+] $u in Remote Desktop Users" }
    catch { Write-Host "[=] already member or failed: $($_.Exception.Message)" }
} -ArgumentList $User

Get-ADUser $User -Server $DomainController | Select-Object SamAccountName, Enabled
