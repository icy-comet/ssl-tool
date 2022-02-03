# What's this?

> A simple interactive CLI wrapper around openssl to make self-signing SSL certs easy.

Self-signed SSL certs are meant for ensuring a consistent `https` development environment or for getting rid of "Your connection is not private" messages in homelab.

## Dependencies
- Python 3
- openssl

## Usage
Download the script and just run it.

```bash
python ./ssl-tool.py --help
```

The script eliminates the need to create a `extfile` manually.

## Contributing
Pull requests, feature requests, and issues are always welcome.

## Install the CA Certificate

To trust the SSL certificates created with this tool, the root CA certificate must be installed beforehand.

### On Windows

```powershell
Import-Certificate -FilePath "<path-to-CA-certificate>" -CertStoreLocation Cert:\LocalMachine\Root
```

- `-CertStoreLocation` can be set to `Cert:\CurrentUser\Root` to only install the CA certificate for the current logged in user.
- Refer the documentation [here.](https://docs.microsoft.com/en-us/powershell/module/pki/import-certificate?view=windowsserver2022-ps)

OR

```cmd
certutil.exe -addstore root C:\ca.pem
```

- `certutil.exe` is a built-in tool (classic `System32` one) and adds a system-wide trust anchor.

### On Android

The exact steps vary device-to-device.

- Open phone's settings
- Locate `Encryption and Credentials` section. It is generally found under `Settings > Security > Encryption and Credentials`
- Choose `Install a certificate`
- Choose `CA Certificate`
- Locate the certificate file on your SD Card/Internal storage with the file manager.
- Select to load it.
- Done!

### On Debian and Derivativess
- Move the CA certificate to `/usr/local/share/ca-certificates` or a sub-dir in that path.
- Now run:
```bash
sudo update-ca-certificates
```
Refer the documentation [here](https://wiki.debian.org/Self-Signed_Certificate) and [here.](https://manpages.debian.org/buster/ca-certificates/update-ca-certificates.8.en.html)

### On Fedora
- Move the CA certificate to `/etc/pki/ca-trust/source/anchors/` or `/usr/share/pki/ca-trust-source/anchors/`
- Now run (with sudo if necessary):
```bash
update-ca-trust
```
Refer the documentation [here.](https://docs.fedoraproject.org/en-US/quick-docs/using-shared-system-certificates/)