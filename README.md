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

```
usage: ssl-tool.py [-h] {create,install} ...

interactive CLI wrapper around openssl to make self-signing SSL certs easy

positional arguments:
  {create,install}  subcommands
    create          create a cert
    install         install a cert

options:
  -h, --help        show this help message and exit
```

```
usage: ssl-tool.py create [-h] {CA,SSL}

positional arguments:
  {CA,SSL}    create a CA cert or an individual SSL cert

options:
  -h, --help  show this help message and exit
```

```
usage: ssl-tool.py install [-h] {CA}

positional arguments:
  {CA}        install a CA cert

options:
  -h, --help  show this help message and exit
```

The script eliminates the need to create a `extfile` manually. And can even auto-install the CA certificate for you.

If you choose to auto-install the CA certificate, please note that escalated privileges are required for it. Windows users must run the script in a shell ran as administrator and Linux users must run the script with sudo or a similar privilege escalation tool. The script doesn't support auto-install for Macs yet.

The script has been currently tested on Windows 10, Windows 11, Ubuntu 20.04 and Debian 11.

## Contributing
Pull requests, feature requests, and issues are always welcome.

## Install the CA Certificate

To trust the SSL certificates created with this tool, the root CA certificate must be installed beforehand. In case you want/need to do it manually:

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
- Filename should end in `.crt`. The `.pem` file this wrapper generates, can be directly renamed to `.crt` according to the internet.
- Refer the documentation [here](https://wiki.debian.org/Self-Signed_Certificate) and [here.](https://manpages.debian.org/buster/ca-certificates/update-ca-certificates.8.en.html)

### On Fedora
- Move the CA certificate to `/etc/pki/ca-trust/source/anchors/` or `/usr/share/pki/ca-trust-source/anchors/`
- Now run (with sudo if necessary):
```bash
update-ca-trust
```
- `.pem` file can be used directly here.
- Refer the documentation [here.](https://docs.fedoraproject.org/en-US/quick-docs/using-shared-system-certificates/)