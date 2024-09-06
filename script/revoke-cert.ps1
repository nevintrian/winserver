param (
    [string]$SubjectName
)

$storePath = "Cert:\CurrentUser\My"
$cert = Get-ChildItem -Path $storePath | Where-Object { $_.Subject -like "*$SubjectName*" }

if ($cert) {
    $thumbprint = $cert.Thumbprint
    $serialNumber = $cert.SerialNumber
    $certutilPath = "C:\Windows\System32\certutil.exe"
    $revokeReason = 0  # Unspecified reason
    $revokeCommand = "$certutilPath -revoke $serialNumber $revokeReason"
    $output = Invoke-Expression $revokeCommand 2>&1

    if ($LASTEXITCODE -eq 0) {
        Write-Output "Certificate with Subject Name: '$SubjectName', thumbprint: $thumbprint and serial number: $serialNumber has been revoked."
    } else {
        Write-Output "Failed to revoke certificate with Subject Name '$SubjectName'."
        Write-Output "Error Output: $output"
    }
} else {
    Write-Output "Certificate with Subject Name '$SubjectName' not found."
}
