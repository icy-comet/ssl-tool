from sys import exit
from os import fsync
from typing import List
from pathlib import Path
from platform import system
from signal import SIGINT, signal
from argparse import ArgumentParser, Namespace
from subprocess import run, CalledProcessError


def sigint_handler(*args):
    print("\n\nExiting...")
    exit(0)


# do not raise KeyboardInterrupt error on Ctrl+C
signal(SIGINT, sigint_handler)


class CACert:
    def __init__(self):
        self._key: Path = None
        self._path: Path = None

    @property
    def key(self) -> Path:
        return self._key

    @key.setter
    def key(self, path: str) -> Path:
        if path and path.endswith(".pem"):
            self._key = Path(path).resolve()
        else:
            raise ValueError("Invalid key path supplied.")

    @property
    def path(self) -> Path:
        return self._path

    @path.setter
    def path(self, path: str) -> None:
        if path.endswith(".pem"):
            if path:
                path = Path(path).resolve()
                if path == self.key:
                    raise ValueError("Key and Certificate path cannot be same.")
                else:
                    self._path = path
            else:
                self._path = self._key.parent + "ssl_certificate.pem"
        else:
            raise ValueError("Cert path must end with .pem extension.")


class SSLCert(CACert):

    # inheriting CACert for key and path properties
    def __init__(self):
        super().__init__()
        self._common_name: str = None
        self._alt_ips: list = []
        self._alt_dns: list = []
        self.ca_cert = CACert()

    @property
    def common_name(self) -> str:
        return self._common_name

    @common_name.setter
    def common_name(self, name: str) -> None:
        if name:
            self._common_name = name
        else:
            raise ValueError("Subject Common Name is required.")

    @property
    def alt_ips(self) -> List[str]:
        return self._alt_ips

    @alt_ips.setter
    def alt_ips(self, ips: str) -> None:
        if ips:
            self._alt_ips = [ip.strip() for ip in ips.split(",")]
        else:
            pass

    @property
    def alt_dns(self) -> List[str]:
        return self._alt_dns

    @alt_dns.setter
    def alt_dns(self, dns_ids: str) -> None:
        if dns_ids:
            dns_ids = [dns_id.strip() for dns_id in dns_ids.split(",")]
        else:
            pass


def install_ca(cert: Path) -> int:
    os_type = system().lower()
    if os_type == "linux":
        # platform.freedesktop_os_release() is only available in Python 3.10+
        # os-release Documentation:
        # https://www.freedesktop.org/software/systemd/man/os-release.html
        try:
            f = open("/etc/os-release", "r")
        except FileNotFoundError:
            f = open("/usr/lib/os-release", "r")
        except:
            print("\nCouldn't determine your OS.")
            return 0

        os_data = {
            key: val.strip('\n "') for key, val in [line.split("=") for line in f]
        }
        f.close()

        try:
            if "debian" in [os_data.get("ID"), os_data.get("ID_LIKE")]:
                run(
                    ["cp", f"{cert}", f"/usr/local/share/ca-certificates/{cert.name}"],
                    check=True,
                )
                run("update-ca-certificates", check=True)
            elif "fedora" in [os_data.get("ID"), os_data.get("ID_LIKE")]:
                run(
                    [
                        "cp",
                        f"{cert}",
                        f"/usr/share/pki/ca-trust-source/anchors/{cert.name}",
                    ],
                    check=True,
                )
                run("update-ca-trust", check=True)
            else:
                print(
                    "\nCouldn't identify your distribution. Kindly file an issue over at GitHub."
                )
                return 0
        except CalledProcessError:
            print("\nSomething went wrong with privileges.")
            return 0
    elif os_type == "windows":
        try:
            run(
                ["certutil.exe", "-addstore", "root", f"{cert}"], shell=True, check=True
            )
        except:
            print("\nSomething went wrong with privileges.")
            return 0

    print("\n=============================")
    print("Installed the CA Certificate!")
    print("=============================")
    return 1


def install_parser_handler(parsed_args: Namespace) -> None:
    cert_type = parsed_args.cert_type

    try:
        if cert_type.lower() == "ca":
            path = Path(input("Path to the public CA Cert:")).resolve()

            if not path.exists() and path.name.endswith((".pem", ".crt")):
                raise ValueError("Invalid path supplied.")

            print()
            c = install_ca(path)

            if not c:
                print("Couldn't install the CA Certificate.")
    except ValueError as e:
        print(str(e))
        return

    return


def create_parser_handler(parsed_args: Namespace) -> None:
    cert_type = parsed_args.cert_type

    print("\n==========")
    print("Starting...")
    print("===========")

    print("\n(Relative paths to the current working directory work as well.)\n")

    try:
        if cert_type.lower() == "ssl":
            new_ssl_cert = SSLCert()

            print(
                "\n(Should end in .pem extension. Generate beforehand if not available.)"
            )
            new_ssl_cert.ca_cert.key = input("Path to the CA key file:")

            if not new_ssl_cert.ca_cert.key.exists():
                raise ValueError("Cannot find the CA key.")

            print(
                "\n(Should end in .pem extension. Generate beforehand if not available.)"
            )
            new_ssl_cert.ca_cert.path = input("Path to the CA certificate:")

            if not new_ssl_cert.ca_cert.path.exists():
                raise ValueError("Cannot find the CA certificate.")

            print(
                "\n(Should end in .pem extension. If it doesn't exist, a new key file will be created at this path.)"
            )
            new_ssl_cert.key = input("Path to the (new) key file:")

            print(
                "\n(Should end in .pem extension. By default, the certificate will be created in the same directory as the key's.)"
            )
            new_ssl_cert.path = input("Path to the new SSL certificate:")

            print(
                "\n(Subject Common Name is the value in the 'Issued to' field of the certificate.)"
            )
            new_ssl_cert.common_name = input("Subject Common Name for the certificate:")

            print("\n(Should be a comma separated list.)")
            new_ssl_cert.alt_ips = input("IP addresses used to identify the subject:")

            print("\n(Should be a comma separated list.)")
            new_ssl_cert.alt_dns = input("DNS entries used to identify the subject:")

            # catch wrong passphrase
            try:
                if not new_ssl_cert.key.exists():
                    # Create a new RSA key
                    run(
                        [
                            "openssl",
                            "genrsa",
                            "-out",
                            f"{new_ssl_cert.key}",
                            "4096",
                        ],
                        check=True,
                    )

                # Create a Certificate Signing Request (CSR)
                run(
                    [
                        "openssl",
                        "req",
                        "-subj",
                        f"/CN={str(new_ssl_cert.common_name)}",
                        "-sha256",
                        "-new",
                        "-key",
                        f"{new_ssl_cert.key}",
                        "-out",
                        f"{new_ssl_cert.path.parent / 'cert.csr'}",
                    ],
                    check=True,
                )

                dns_txt = ""
                if new_ssl_cert.alt_dns:
                    for record in new_ssl_cert.alt_dns:
                        dns_txt += f"DNS:{record},"

                ips_txt = ""
                if new_ssl_cert.alt_ips:
                    for ip in new_ssl_cert.alt_ips:
                        ips_txt += f"IP:{ip},"
                    ips_txt = ips_txt.rstrip(",")

                # cannot use NamedTemporaryFile due to Windows limitations
                extfile = new_ssl_cert.path.parent / "extfile.cnf"
                with open(extfile, mode="w") as f:
                    f.write("subjectAltName=" + dns_txt + ips_txt)
                    f.flush()
                    # ensure the data is written to the disk
                    fsync(f.fileno())

                # Create the Certificate
                run(
                    [
                        "openssl",
                        "x509",
                        "-req",
                        "-days",
                        "365",
                        "-sha256",
                        "-in",
                        str(new_ssl_cert.path.parent / "cert.csr"),
                        "-CA",
                        f"{new_ssl_cert.ca_cert.path}",
                        "-CAkey",
                        f"{new_ssl_cert.ca_cert.key}",
                        "-CAcreateserial",
                        "-out",
                        f"{new_ssl_cert.path}",
                        "-extfile",
                        f"{extfile}",
                    ],
                    check=True,
                )
            except CalledProcessError as e:
                print("Wrong password provided.")
                return

            print("\n==============================")
            print("New SSL certificate generated!")
            print("==============================")
            return
        elif cert_type.lower() == "ca":
            new_ca_cert = CACert()

            print("\n(Should end in .pem extension)")
            new_ca_cert.key = input("Path to the (new) CA key file:")

            print("\n(Should end in .pem extension)")
            new_ca_cert.path = input("Path to the new CA certificate:")

            # output formatting
            print()

            # catch wrong passphrase
            try:
                run(
                    [
                        "openssl",
                        "genrsa",
                        "-aes256",
                        "-out",
                        f"{new_ca_cert.key}",
                        "4096",
                    ],
                    check=True,
                )

                print("\nCreating the certificate...\n")

                run(
                    [
                        "openssl",
                        "req",
                        "-new",
                        "-x509",
                        "-days",
                        "365",
                        "-key",
                        f"{new_ca_cert.key}",
                        "-sha256",
                        "-out",
                        f"{new_ca_cert.path}",
                    ],
                    check=True,
                )
            except CalledProcessError as e:
                print("Wrong passphrase provided.")
                return

            print("\n==============================")
            print("New CA Certificate generated!")
            print("==============================")

            auto_inst = input("\nAttempt auto-install of the CA certificate?[y/n]")

            if auto_inst.lower() == "y":
                c = install_ca(new_ca_cert.path)
                if not c:
                    print("Couldn't auto-install the CA certificate.")
            return
    except ValueError as e:
        print(str(e))
        return


parser = ArgumentParser(
    description="interactive CLI wrapper around openssl to make self-signing SSL certs easy"
)

subparsers = parser.add_subparsers(help="subcommands")

create_parser = subparsers.add_parser("create", help="create a cert")
create_parser.add_argument(
    "cert_type",
    choices=["CA", "SSL"],
    help="create a CA cert or an individual SSL cert",
)
create_parser.set_defaults(handler=create_parser_handler)

install_parser = subparsers.add_parser("install", help="install a cert")
install_parser.add_argument(
    "cert_type",
    choices=["CA",],
    help="install a CA cert",
)
install_parser.set_defaults(handler=install_parser_handler)

# gets invoked if no sub-command is provided
def defaults_handler(*args):
    global parser
    parser.print_help()


parser.set_defaults(handler=defaults_handler)

if __name__ == "__main__":
    parsed_args = parser.parse_args()
    parsed_args.handler(parsed_args)
