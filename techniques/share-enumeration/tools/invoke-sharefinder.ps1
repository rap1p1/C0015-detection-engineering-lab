function Invoke-ShareFinder {
    [CmdletBinding()] param([switch]$CheckShareAccess, [string]$ComputerName, [string]$OutFile = 'C:\ProgramData\found_shares.txt')
    $computers = New-Object System.Collections.Generic.List[string]
    if ($ComputerName) { $computers.Add($ComputerName) }
    else {
        $computers.Add($env:COMPUTERNAME)
        $dc = $env:LOGONSERVER -replace '^\\\\',''
        if ($dc -and $dc -ne $env:COMPUTERNAME) { $computers.Add($dc) }
        try {
            $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            foreach ($c in $dom.GetDirectoryEntry().Children) {
                if ($c.objectClass -contains 'computer' -and $c.dNSHostName) { $computers.Add([string]$c.dNSHostName) }
            }
        } catch { }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in ($computers | Sort-Object -Unique)) {
        $shares = @()
        try { $shares = Get-WmiObject Win32_Share -ComputerName $c -ErrorAction Stop } catch {
            try { $shares = Get-SmbShare -CimSession $c -ErrorAction Stop } catch { }
        }
        if (-not $shares) { $rows.Add([pscustomobject]@{ Computer = $c; Share = '(unreachable)'; Accessible = $false }); continue }
        foreach ($s in $shares) {
            $name = $s.Name
            $access = $null
            if ($CheckShareAccess) { $access = Test-Path "\\$c\$name" -ErrorAction SilentlyContinue }
            $rows.Add([pscustomobject]@{ Computer = $c; Share = $name; Accessible = $access })
        }
    }
    $rows | Format-Table -AutoSize | Out-File -FilePath $OutFile -Encoding ascii
    Write-Verbose "share enumeration complete: $($rows.Count) shares"
}
