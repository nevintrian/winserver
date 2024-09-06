const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.json());

const scriptDir = 'C:\\Users\\Administrator\\Documents\\api\\script';
const outputDir = 'C:\\Users\\Administrator\\Documents\\api\\output_user';

const runPowerShellCommand = (command) => {
    return new Promise((resolve, reject) => {
        exec(`powershell.exe -NoProfile -Command "${command}"`, (error, stdout, stderr) => {
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

const writeFile = (filePath, content) => {
    return new Promise((resolve, reject) => {
        fs.writeFile(filePath, content, (err) => {
            if (err) {
                return reject(err);
            }
            resolve();
        });
    });
};

const readFile = (filePath) => {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                return reject(err);
            }
            resolve(data);
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
        const stdout = await runPowerShellCommand(`& "${scriptPath}" -CAName "${escapedCaName}"`);
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
        const stdout = await runPowerShellCommand(`& "${scriptPath}" -SubjectName "${escapedSubjectName}"`);
        res.status(200).json({ message: stdout.trim() });
    } catch (error) {
        console.error(`Error: ${error.error}`);
        res.status(500).json({ error: error.error, details: error.stderr });
    }
});

app.post('/create-user-and-certificate', async (req, res) => {
    console.log("Received a request to create user and certificate...");
    const { Name, UserPassword, Group, SubjectName, SubjectAltName, TemplateName, CAConfig, PfxPassword, Domain } = req.body;

    if (!Name || !UserPassword || !Group || !SubjectName || !SubjectAltName || !TemplateName || !CAConfig || !PfxPassword || !Domain) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const createUserCommand = `$Password = ConvertTo-SecureString '${UserPassword}' -AsPlainText -Force; New-ADUser -Name '${Name}' -GivenName '${Name}' -SamAccountName '${Name}' -UserPrincipalName '${Name}@${Domain}' -DisplayName '${Name}' -AccountPassword $Password -ChangePasswordAtLogon $false -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true; Add-ADGroupMember -Identity '${Group}' -Members '${Name}';`;

    try {
        await runPowerShellCommand(createUserCommand);
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

        const infPath = path.join(outputDir, `${Name}-request.inf`);
        const reqFilePath = path.join(outputDir, `${Name}-request.req`);
        const certFilePath = path.join(outputDir, `${Name}.cer`);
        const pfxFilePath = path.join(outputDir, `${Name}.pfx`);

        await writeFile(infPath, infContent);

        const certreqCommand = `certreq -config "${formattedCAConfig}" -new "${infPath}" "${reqFilePath}" ; certreq -config "${formattedCAConfig}" -submit "${reqFilePath}" "${certFilePath}" | Out-Null`;
        await runPowerShellCommand(certreqCommand);
        console.log("Certificate created successfully");

        const installCertCommand = `Import-Certificate -FilePath "${certFilePath}" -CertStoreLocation "Cert:\\CurrentUser\\My"`;
        await runPowerShellCommand(installCertCommand);

        const thumbprintCommand = `Get-ChildItem -Path Cert:\\CurrentUser\\My | Where-Object { $_.Subject -eq 'CN=${SubjectName}' } | Select-Object -ExpandProperty Thumbprint`;
        const thumbprint = (await runPowerShellCommand(thumbprintCommand)).trim();

        if (!thumbprint) {
            return res.status(500).json({ error: 'Certificate not found or private key is missing' });
        }

        const pfxCommand = `Export-PfxCertificate -Cert "Cert:\\CurrentUser\\My\\${thumbprint}" -FilePath "${pfxFilePath}" -Password (ConvertTo-SecureString -String "${PfxPassword}" -AsPlainText -Force)`;
        await runPowerShellCommand(pfxCommand);
        console.log("Certificate exported successfully");

        const convertCerCommand = `openssl pkcs12 -in "${pfxFilePath}" -clcerts -nokeys -out "${certFilePath}" -passin pass:${PfxPassword}`;
        const convertKeyCommand = `openssl pkcs12 -in "${pfxFilePath}" -nocerts -out "${pfxFilePath}.key" -passin pass:${PfxPassword} -nodes`;

        await runPowerShellCommand(`cmd /c "${convertCerCommand}"`);
        await runPowerShellCommand(`cmd /c "${convertKeyCommand}"`);

        const certData = await readFile(certFilePath);
        const keyData = await readFile(`${pfxFilePath}.key`);

        // Clean up certificate and private key
        const cleanCertData = certData.replace(/Bag Attributes[\s\S]*?-----BEGIN CERTIFICATE-----/, '-----BEGIN CERTIFICATE-----').replace(/-----END CERTIFICATE-----[\s\S]*/, '-----END CERTIFICATE-----').trim();
        const cleanKeyData = keyData.replace(/Bag Attributes[\s\S]*?-----BEGIN PRIVATE KEY-----/, '-----BEGIN PRIVATE KEY-----').replace(/-----END PRIVATE KEY-----[\s\S]*/, '-----END PRIVATE KEY-----').trim();

        // Publish the certificate to Active Directory
        const publishCertCommand = `certutil -dspublish "${certFilePath}" "User"`;

        try {
            const publishStdout = await runPowerShellCommand(publishCertCommand);
            console.log("Certificate published to Active Directory successfully");
        } catch (publishError) {
            console.error(`Failed to publish certificate to Active Directory: ${publishError.error}`);
            return res.status(500).json({ error: 'Failed to publish certificate to Active Directory', details: publishError.stderr });
        }

        res.status(200).json({ certificate: cleanCertData, private_key: cleanKeyData });

    } catch (error) {
        console.error(`Error: ${error.error}`);
        res.status(500).json({ error: error.error, details: error.stderr });
    }
});

const port = 3000;
app.listen(port, () => {
    console.log(`API server running on port ${port}`);
});
