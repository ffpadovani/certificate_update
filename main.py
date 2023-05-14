import os
import sys
import requests
import logging
from logging.handlers import RotatingFileHandler
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def download(url: str, dest_path: str):
    filename = url.split('/')[-1].replace(" ", "_")
    file_path = os.path.join(dest_path, filename)

    r = requests.get(url, stream=True)
    if r.ok:
        logger.info(f"Salvando, {os.path.abspath(file_path)}")
        with open(file_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024 * 8):
                if chunk:
                    f.write(chunk)
                    f.flush()
                    os.fsync(f.fileno())
    else:  # HTTP status code 4XX/5XX
        logger.error({"status_code": r.status_code, "message": r.text})


def get_cer_info(cert: str):
    certDecoded = x509.load_pem_x509_certificate(
        str.encode(cert), default_backend())
    print(certDecoded)


def restart_service(service_name: str):
    logger.info(f"Reiniciando serviço '{service_name}'")


def main():
    path = "/etc/ssl/certs"
    url = "https://i216.ffpadovani.tech"
    cer_files = {"cert": "fullchain.pem", "key": "privkey.pem"}
    service_name = sys.argv[1]

    logger.info("####  Starting certificate updater  ####")
    logger.debug(f"Loadins files in '{path}' from verification.")
    # Listing all SSL certificates installed on the server
    local_cert_list = os.listdir(path=path)

    logger.debug(
        "Verifying that the files 'fullchain.pem' and 'privkey.pem' exist")
    # Verifying that SSL certificate exist on the server
    check_files = dict(map(lambda x: (x, True) if x in local_cert_list else (
        x, False), cer_files.values()))

    check_download = False

    # Checking if the files exist, if one of them does not exist the variable 'check_download' is changed to True
    for k, v in check_files.items():
        if not v:
            logger.info(f"{path}/{k} not found")
            check_download = True
            logger.debug({"check_download": check_download})

    # If the 'check_download' variable is True, start downloading the SSL certificate.
    if check_download:
        logger.debug("Starting to download the SSL Certificate files.")
        [download(url=f"{url}/{filename}", dest_path=path)
         for filename in cer_files.values()]
        if service_name:
            restart_service(service_name=service_name)
        return

    # Loadind the current certificate to compare expiration date with ssl certificate in the server
    try:
        logger.info('Loading current certificate to verification')
        current_cert = x509.load_pem_x509_certificate(
            open(f"{path}/{cer_files['cert']}", "rb").read(), default_backend())
    except ValueError as e:
        logger.error(str(e))
        logger.debug("Starting to download the SSL Certificate files.")
        [download(url=f"{url}/{filename}", dest_path=path)
         for filename in cer_files.values()]
        if service_name:
            restart_service(service_name=service_name)
        return

    try:
        logger.info('Loading SSL certificate from server for verification')
        r = requests.get(f"{url}/{cer_files['cert']}", stream=True)
        if not r.ok:
            logger.error({"status_code": r.status_code, "message": r.text})
            return
        new_cert = x509.load_pem_x509_certificate(
            r.text.encode(), default_backend())
    except Exception as e:
        logger.error(str(e))

    if current_cert.not_valid_after <= new_cert.not_valid_after:
        logger.info("Current SSL Certificate is valid")
        return

    logger.info("Updating SSL Certificate from this server")
    [download(url=f"{url}/{filename}", dest_path=path)
     for filename in cer_files.values()]
    if service_name:
        restart_service(service_name=service_name)


if __name__ == "__main__":
    logging.basicConfig(
        handlers=[RotatingFileHandler(
            './log/certificate_updater.log', maxBytes=100000, backupCount=10)],
        level=logging.DEBUG,
        format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
        datefmt='%Y-%m-%dT%H:%M:%S')

    logger = logging.getLogger(__name__)

    main()
