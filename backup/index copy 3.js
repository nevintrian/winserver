const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.json());

const scriptDir = 'C:\\Users\\Administrator\\Documents\\api\\script';
const requestDir = 'C:\\Users\\Administrator\\Documents\\api\\request';

const runPowerShellScript = (scriptPath, args = '') => {
    return new Promise((resolve, reject) => {
        exec(`powershell.exe -NoProfile -File "${scriptPath}" ${args}`, (error, stdout, stderr) => {
            if (error) {
                return reject({ error: `exec error: ${error}`, stderr });
            }
            if (stderr) {
                return reject({ error: stderr });
            }
            resolve(stdout);
        });
    });
};

app.get('/', (req, res) => {
    res.status(200).json({ message: 'API Active' });
});


app.get('/export-ca-cert', async (req, res) => {
    const caName = req.query.CAName;
    if (!caName) {
        return res.status(400).json({ error: 'CAName parameter is required' });
    }

    const scriptPath = path.join(scriptDir, 'export-ca-cert.ps1');
    const escapedCaName = caName.replace(/"/g, '""');

    try {
        const stdout = await runPowerShellScript(scriptPath, `-CAName "${escapedCaName}"`);
        res.status(200).json({ certificate: stdout.trim() });
    } catch (error) {
        console.error(`Error: ${error.error}`);
        res.status(500).json({ error: error.error, details: error.stderr });
    }
});

app.post('/revoke-cert', async (req, res) => {
    const { SubjectName } = req.body;

    if (!SubjectName) {
        return res.status(400).json({ error: 'SubjectName parameter is required' });
    }

    const scriptPath = path.join(scriptDir, 'revoke-cert.ps1');
    const escapedSubjectName = SubjectName.replace(/"/g, '""');

    try {
        const stdout = await runPowerShellScript(scriptPath, `-SubjectName "${escapedSubjectName}"`);
        res.status(200).json({ 
            message: stdout.trim()
        });
    } catch (error) {
        console.error(`Error: ${error.error}`);
        res.status(500).json({ 
            error: error.error, 
            details: error.stderr 
        });
    }
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
        const infContent = 
`[Version]
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

        const infPath = path.join(__dirname, `${Name}-request.inf`);
        const reqFilePath = path.join(__dirname, `${Name}-request.req`);
        const certFilePath = path.join(__dirname, `${Name}.cer`);
        const pfxFilePath = path.join(__dirname, `${Name}.pfx`);

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

                            // Convert .pfx to .cer and .key using OpenSSL commands
                            const convertCerCommand = `openssl pkcs12 -in "${pfxFilePath}" -clcerts -nokeys -out "${certFilePath}" -passin pass:${PfxPassword}`;
                            const convertKeyCommand = `openssl pkcs12 -in "${pfxFilePath}" -nocerts -out "${pfxFilePath}.key" -passin pass:${PfxPassword} -nodes`;

                            exec(`cmd /c "${convertCerCommand}"`, (error, stdout, stderr) => {
                                if (error) {
                                    console.error(`exec error: ${error}`);
                                    console.error(stderr);
                                    return res.status(500).json({ error: 'Failed to convert PFX to CER', details: stderr });
                                }

                                exec(`cmd /c "${convertKeyCommand}"`, (error, stdout, stderr) => {
                                    if (error) {
                                        console.error(`exec error: ${error}`);
                                        console.error(stderr);
                                        return res.status(500).json({ error: 'Failed to convert PFX to KEY', details: stderr });
                                    }

                                    // Read .cer and .key files
                                    fs.readFile(certFilePath, 'utf8', (err, certData) => {
                                        if (err) {
                                            console.error(`Failed to read .cer file: ${err}`);
                                            return res.status(500).json({ error: 'Failed to read .cer file', details: err.message });
                                        }

                                        fs.readFile(`${pfxFilePath}.key`, 'utf8', (err, keyData) => {
                                            if (err) {
                                                console.error(`Failed to read .key file: ${err}`);
                                                return res.status(500).json({ error: 'Failed to read .key file', details: err.message });
                                            }

                                        // Clean up certificate and private key
                                        const cleanCertData = certData.replace(/Bag Attributes[\s\S]*?-----BEGIN CERTIFICATE-----/, '-----BEGIN CERTIFICATE-----').replace(/-----END CERTIFICATE-----[\s\S]*/, '-----END CERTIFICATE-----').trim();
                                        const cleanKeyData = keyData.replace(/Bag Attributes[\s\S]*?-----BEGIN PRIVATE KEY-----/, '-----BEGIN PRIVATE KEY-----').replace(/-----END PRIVATE KEY-----[\s\S]*/, '-----END PRIVATE KEY-----').trim();
                                        
                                        // Respond with the certificate and private key
                                        res.status(200).json({ certificate: cleanCertData, private_key: cleanKeyData });

                                            // Optionally, delete the files after sending if they are no longer needed
                                            // fs.unlink(infPath, (err) => { if (err) console.error(`Failed to delete INF file: ${err}`); });
                                            // fs.unlink(reqFilePath, (err) => { if (err) console.error(`Failed to delete REQ file: ${err}`); });
                                            // fs.unlink(certFilePath, (err) => { if (err) console.error(`Failed to delete CER file: ${err}`); });
                                            // fs.unlink(pfxFilePath, (err) => { if (err) console.error(`Failed to delete PFX file: ${err}`); });
                                            // fs.unlink(`${pfxFilePath}.key`, (err) => { if (err) console.error(`Failed to delete KEY file: ${err}`); });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});


const port = 3000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
