from sys import exit
from os import fsync
from typing import List
from pathlib import Path
from subprocess import run
from signal import SIGINT, signal
from tempfile import TemporaryFile
from argparse import ArgumentParser, Namespace


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
                self._path = Path(path).resolve()
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


def cli_handler(parsed_args: Namespace) -> None:
    cert_type = parsed_args.cert_type

    print("\n==========")
    print("Starting...")
    print("===========")

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
                "\n(Should end in .pem extension. By default, the certificate will be created in the supplied key's directory.)"
            )
            new_ssl_cert.path = input("Path to the new SSL certificate:")

            print(
                "\nSubject Common Name is the value in the 'Issued to' field of the browser."
            )
            new_ssl_cert.common_name = input("Subject Common Name for the certificate:")

            print("\n(Should be a comma separated list.)")
            new_ssl_cert.alt_ips = input("IP addresses used to identify the subject:")

            print("\n(Should be a comma separated list.)")
            new_ssl_cert.alt_dns = input("DNS entries used to identify the subject:")

            if not new_ssl_cert.key.exists():
                # Create a new RSA key
                run(
                    [
                        "openssl",
                        "genrsa",
                        "-aes256",
                        "-out",
                        f"{new_ssl_cert.key}",
                        "4096",
                    ],
                    shell=True,
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
                    f"{new_ssl_cert.key.parent + 'cert.csr'}",
                ],
                shell=True,
            )

            if new_ssl_cert.alt_dns:
                dns_txt = ""
                for record in new_ssl_cert.alt_dns:
                    dns_txt += f"DNS:{record},"
                if len(new_ssl_cert.alt_dns) < 2:
                    dns_txt.rstrip(",")
            if new_ssl_cert.alt_ips:
                ips_txt = ""
                for ip in new_ssl_cert.alt_ips:
                    ips_txt += f"IP:{ip},"
                if len(new_ssl_cert.alt_ips) < 2:
                    ips_txt.rstrip(",")

            tempf = TemporaryFile("w+", buffering=0, encoding="utf-8")
            tempf.write("subjectAltName=" + dns_txt + ips_txt)
            # ensure the data is written to the disk
            fsync(tempf.fileno())

            # Create the Ceritificate
            run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-days",
                    "365",
                    "-sha256",
                    "-in",
                    str(new_ssl_cert.key.parent + "cert.csr"),
                    "-CA",
                    f"{new_ssl_cert.ca_cert.key}",
                    "-CAkey",
                    f"{new_ssl_cert.ca_cert.key}",
                    "-CAcreateserial",
                    "-out",
                    f"{new_ssl_cert.path}",
                    "-extfile",
                    f"{tempf.name}",
                ],
                shell=True,
            )

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

            run(["openssl", "genrsa", "-aes256", "-out", f"{new_ca_cert.key}", "4096"])

            print("\nCreating the certificate...")

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
                ]
            )

            print("\n==============================")
            print("New CA Certificate generated!")
            print("==============================")
            return
    except ValueError as e:
        print(str(e))


parser = ArgumentParser(
    description="interactive CLI wrapper around openssl make self-signing SSL certs easy"
)

parser.add_argument(
    "cert_type",
    choices=["CA", "SSL"],
    help="create a CA cert or an individual SSL cert",
)

parser.set_defaults(handler=cli_handler)

if __name__ == "__main__":
    parsed_args = parser.parse_args()
    parsed_args.handler(parsed_args)