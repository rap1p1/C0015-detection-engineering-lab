<#
.SYNOPSIS
    Create the lab account model and the backup server shares.
.DESCRIPTION
    Idempotent. Run on DC01 with the ActiveDirectory module available. Passwords are prompted and are
    never written to disk, the event log, or the console.

    Accounts:
      duc.user    interactive victim, local administrator on WS01
      bk.admin    backup server administrator, local administrator on FS01
      it.admin    domain administrator for lab administration
      svc_backup  service identity for the backup agent

    Membership:
      C0015\WS01$ is added to the local Administrators group of the backup server so a SYSTEM
      context on the workstation can reach it through the machine account.
.EXAMPLE
    .\New-LabAccounts.ps1 -BackupServer FS01
#>
[CmdletBinding()]
param(
    [string]$DomainController = $env:COMPUTERNAME,
    [string]$BackupServer     = 'FS01',
    [string]$ShareRoot        = 'C:\C0015\shares',
    [switch]$SkipShares
)

Import-Module ActiveDirectory -ErrorAction Stop

$domain = (Get-ADDomain).DNSRoot
$netbios = (Get-ADDomain).NetBIOSName

$accounts = @(
    @{ Sam = 'duc.user';   Name = 'Duc User';          Desc = 'Interactive user, workstation victim' },
    @{ Sam = 'bk.admin';   Name = 'Backup Admin';      Desc = 'Backup server administrator' },
    @{ Sam = 'it.admin';   Name = 'IT Admin';          Desc = 'Lab administration' },
    @{ Sam = 'svc_backup'; Name = 'Backup Service';    Desc = 'Backup agent service identity' }
)

foreach ($a in $accounts) {
    $existing = Get-ADUser -Filter "SamAccountName -eq '$($a.Sam)'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[=] $($a.Sam) exists"
        continue
    }
    $pw = Read-Host -AsSecureString "Password for $($a.Sam)"
    New-ADUser -SamAccountName $a.Sam -Name $a.Name -DisplayName $a.Name `
        -Description $a.Desc -AccountPassword $pw -Enabled $true `
        -PasswordNeverExpires $true -CannotChangePassword $false `
        -Path (Get-ADDomain).UsersContainer
    Write-Host "[+] created $($a.Sam)"
}

# service logon right for the backup service identity
$svc = Get-ADUser -Filter "SamAccountName -eq 'svc_backup'" -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "[i] grant 'Log on as a service' to svc_backup with secedit or the local policy editor on $BackupServer"
}

# backup server: local administrators and shares
$session = New-PSSession -ComputerName $BackupServer -ErrorAction Stop
try {
    Invoke-Command -Session $session -ArgumentList $netbios -ScriptBlock {
        param($netbios)
        foreach ($member in @("$netbios\bk.admin", "$netbios\WS01`$")) {
            $group = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
            try {
                $group.Add("WinNT://$member,user")
                Write-Host "[+] added $member to local Administrators"
            } catch {
                Write-Host "[=] $member already present or not resolvable"
            }
        }
    }

    if (-not $SkipShares) {
        Invoke-Command -Session $session -ArgumentList $ShareRoot -ScriptBlock {
            param($root)
            foreach ($n in 'Backups', 'Shares') {
                $p = Join-Path $root $n
                if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
                if (-not (Get-SmbShare -Name $n -ErrorAction SilentlyContinue)) {
                    New-SmbShare -Name $n -Path $p -FullAccess "$env:USERDOMAIN\Domain Admins" | Out-Null
                    Write-Host "[+] share $n -> $p"
                } else {
                    Write-Host "[=] share $n exists"
                }
            }
        }
    }
}
finally {
    Remove-PSSession $session
}

Write-Host ''
Write-Host 'Verify:'
Write-Host "  Get-ADUser -Filter * | Select SamAccountName,Enabled"
Write-Host "  Invoke-Command -ComputerName $BackupServer -ScriptBlock { Get-LocalGroupMember Administrators }"
