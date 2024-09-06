param (
    [string]$CAName,
    [string]$ExportDirectory = "C:\Users\Administrator\Documents\api\output_ca"
)

$ExportPath = Join-Path -Path $ExportDirectory -ChildPath "$CAName.cer"
$caCert = Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object { $_.Subject -like "*$CAName*" }

if ($caCert) {
    $certBytes = $caCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certBase64 = [System.Convert]::ToBase64String($certBytes)
    $lineLength = 64
    $certBase64Lines = [System.Text.RegularExpressions.Regex]::Matches($certBase64, ".{1,$lineLength}") | ForEach-Object { $_.Value }
    $certPem = "-----BEGIN CERTIFICATE-----`n" +
               ($certBase64Lines -join "`n") + "`n" +
               "-----END CERTIFICATE-----"
    Set-Content -Path $ExportPath -Value $certPem -Encoding Ascii
    Write-Output $certPem
} else {
    Write-Output "CA certificate with name $CAName not found."
}
