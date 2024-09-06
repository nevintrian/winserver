const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.json());

app.get('/', (req, res) => {
    return res.status(200).json({ message: 'API Active' });
});

app.post('/create-user-and-certificate', (req, res) => {
    console.log("Received a request to create user and certificate...");
    const { Name, UserPassword, Group, SubjectName, SubjectAltName, TemplateName, CAConfig, PfxPassword, Domain } = req.body;

    if (!Name || !UserPassword || !Group || !SubjectName || !SubjectAltName || !TemplateName || !CAConfig || !PfxPassword || !Domain) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const createUserCommand = `$Password = ConvertTo-SecureString '${UserPassword}' -AsPlainText -Force; New-ADUser -Name '${Name}' -GivenName '${Name}' -SamAccountName '${Name}' -UserPrincipalName '${Name}@${Domain}' -DisplayName '${Name}' -AccountPassword $Password -ChangePasswordAtLogon $false -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true; Add-ADGroupMember -Identity '${Group}' -Members '${Name}';`;

    exec(`powershell.exe -NoProfile -Command "${createUserCommand}"`, (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            console.error(stderr);
            return res.status(500).json({ error: 'Failed to create user' });
        }
        console.log("User created successfully");

        const formattedCAConfig = CAConfig.replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
        const infContent = `
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=${SubjectName}"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0"
ProviderType = 1
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA256
FriendlyName = "${TemplateName}"
Exportable = TRUE  ; Ensure private key is exportable

[Extensions]
2.5.29.17 = "{text}upn=${SubjectAltName}"

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2 ; Client Authentication

[RequestAttributes]
CertificateTemplate = "${TemplateName}"
`;

        const infPath = path.join('C:\\Users\\Administrator\\Documents\\api\\request', `${Name}-request.inf`);
        const reqFilePath = path.join('C:\\Users\\Administrator\\Documents\\api\\request', `${Name}-request.req`);
        const certFilePath = path.join('C:\\Users\\Administrator\\Documents\\api\\request', `${Name}.cer`);
        const pfxFilePath = path.join('C:\\Users\\Administrator\\Documents\\api\\request', `${Name}.pfx`);

        // Write the INF content to a file
        fs.writeFile(infPath, infContent, (err) => {
            if (err) {
                console.error(`Failed to write INF file: ${err}`);
                return res.status(500).json({ error: 'Failed to write INF file', details: err.message });
            }

            const certreqCommand = `certreq -config "${formattedCAConfig}" -new "${infPath}" "${reqFilePath}" ; certreq -config "${formattedCAConfig}" -submit "${reqFilePath}" "${certFilePath}" | Out-Null`;

            exec(`powershell.exe -NoProfile -Command "${certreqCommand}"`, (error, stdout, stderr) => {
                if (error) {
                    console.error(`exec error: ${error}`);
                    console.error(stderr);
                    return res.status(500).json({ error: 'Failed to create certificate', details: stderr });
                }
                console.log("Certificate created successfully");

                const installCertCommand = `Import-Certificate -FilePath "${certFilePath}" -CertStoreLocation "Cert:\\CurrentUser\\My"`;

                exec(`powershell.exe -NoProfile -Command "${installCertCommand}"`, (error, stdout, stderr) => {
                    if (error) {
                        console.error(`exec error: ${error}`);
                        console.error(stderr);
                        return res.status(500).json({ error: 'Failed to install certificate', details: stderr });
                    }

                    const thumbprintCommand = `Get-ChildItem -Path Cert:\\CurrentUser\\My | Where-Object { $_.Subject -eq 'CN=${SubjectName}' } | Select-Object -ExpandProperty Thumbprint`;

                    exec(`powershell.exe -NoProfile -Command "${thumbprintCommand}"`, (error, stdout, stderr) => {
                        if (error) {
                            console.error(`exec error: ${error}`);
                            console.error(stderr);
                            return res.status(500).json({ error: 'Failed to retrieve certificate thumbprint', details: stderr });
                        }

                        const thumbprint = stdout.trim();

                        if (!thumbprint) {
                            return res.status(500).json({ error: 'Certificate not found or private key is missing' });
                        }

                        const pfxCommand = `Export-PfxCertificate -Cert "Cert:\\CurrentUser\\My\\${thumbprint}" -FilePath "${pfxFilePath}" -Password (ConvertTo-SecureString -String "${PfxPassword}" -AsPlainText -Force)`;

                        exec(`powershell.exe -NoProfile -Command "${pfxCommand}"`, (error, stdout, stderr) => {
                            if (error) {
                                console.error(`exec error: ${error}`);
                                console.error(stderr);
                                return res.status(500).json({ error: 'Failed to export certificate as .pfx', details: stderr });
                            }

                            console.log("Certificate exported successfully");

                            const publishCertCommand = `certutil -dspublish "${certFilePath}" "User"`;

                            exec(`powershell.exe -NoProfile -Command "${publishCertCommand}"`, (error, stdout, stderr) => {
                                if (error) {
                                    console.error(`exec error: ${error}`);
                                    console.error(stderr);
                                    return res.status(500).json({ error: 'Failed to publish certificate to Active Directory', details: stderr });
                                }

                                console.log("Certificate published to Active Directory successfully");

                                // Send the .pfx file as a response
                                res.download(pfxFilePath, `${Name}.pfx`, (err) => {
                                    if (err) {
                                        console.error(`Failed to send .pfx file: ${err}`);
                                        return res.status(500).json({ error: 'Failed to send .pfx file', details: err.message });
                                    }

                                    // Optionally, delete the files after sending if they are no longer needed
                                    // fs.unlink(infPath, (err) => { if (err) console.error(`Failed to delete INF file: ${err}`); });
                                    // fs.unlink(reqFilePath, (err) => { if (err) console.error(`Failed to delete request file: ${err}`); });
                                    // fs.unlink(certFilePath, (err) => { if (err) console.error(`Failed to delete cert file: ${err}`); });
                                    // fs.unlink(pfxFilePath, (err) => { if (err) console.error(`Failed to delete PFX file: ${err}`); });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
