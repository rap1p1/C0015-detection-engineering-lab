<#
.SYNOPSIS
    Verify the properties a detection rule depends on: signature status, version metadata, hash.
.EXAMPLE
    .\verify-module.ps1 -Path C:\Users\Public\compareForfor.jpg
#>
param([Parameter(Mandatory)][string]$Path)

$f = Get-Item -LiteralPath $Path
$sig = Get-AuthenticodeSignature -LiteralPath $Path
$vi = $f.VersionInfo

[pscustomobject]@{
    Path            = $f.FullName
    SizeBytes       = $f.Length
    Extension       = $f.Extension
    SignatureStatus = $sig.Status
    Signer          = $sig.SignerCertificate.Subject
    CompanyName     = $vi.CompanyName
    ProductName     = $vi.ProductName
    FileDescription = $vi.FileDescription
    FileVersion     = $vi.FileVersion
    SHA256          = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
} | Format-List

Write-Host 'Expected: SignatureStatus NotSigned, empty metadata, .jpg extension, PE header present.'
$bytes = [System.IO.File]::ReadAllBytes($Path)[0..1]
Write-Host ("Header: {0}{1}" -f [char]$bytes[0], [char]$bytes[1])
