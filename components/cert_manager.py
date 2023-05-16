import logging
import os

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class CertificateManager:
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def download(self, url: str, dest_path: str, timeout: int = 30):
        filename = url.split('/')[-1].replace(" ", "_")
        file_path = os.path.join(dest_path, filename)

        response = requests.get(url, stream=True, timeout=timeout)
        if response.ok:
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024 * 8):
                    if chunk:
                        f.write(chunk)
                        f.flush()
                        os.fsync(f.fileno())
        else:  # HTTP status code 4XX/5XX
            raise CertUrlException(
                {"status_code": response.status_code, "message": response.text})

    def download_multi(self, url: str, dest_path: str, files: list):
        for filename in files:
            self.download(url=f"{url}/{filename}", dest_path=dest_path,)

    def get_remote_data(self, url: str, timeout: int = 30):
        response = requests.get(url, stream=True, timeout=timeout)
        if not response.ok:
            raise CertUrlException(
                {"status_code": response.status_code, "message": response.text})
        cert_decoded = x509.load_pem_x509_certificate(
            response.text.encode(), default_backend())

        return cert_decoded

    def get_local_data(self, cert: str):
        cert_decoded = x509.load_pem_x509_certificate(cert, default_backend())
        return cert_decoded


class CertUrlException(Exception):
    pass
