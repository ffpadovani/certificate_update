import logging
import os
import sys
from logging.handlers import RotatingFileHandler

from components.cert_manager import CertificateManager, CertUrlException
from components.service_manager import ServiceManager


def main():
    path = "/etc/ssl/certs"
    url = "https://i216.ffpadovani.tech"
    cer_files = {"cert": "fullchain.pem", "key": "privkey.pem"}
    service_name = sys.argv[1]

    cert_control = CertificateManager()
    svc = ServiceManager()

    logger.info("####  Starting certificate updater  ####")
    logger.debug("Loadins files in '%s' from verification.", path)

    # Listing all SSL certificates installed on the server
    local_cert_list = os.listdir(path=path)

    logger.debug(
        "Verifying that the files 'fullchain.pem' and 'privkey.pem' exist")

    # Verifying that SSL certificate exist on the server

    check_files = dict(map(lambda x: (x, True) if x in local_cert_list else (
        x, False), cer_files.values()))

    check_download = False

    # Checking if the files exist, if one of them does not exist the variable
    # 'check_download' is changed to True
    for key, value in check_files.items():
        if not value:
            logger.info("%s/%s not found", path, key)
            check_download = True
            logger.debug({"check_download": check_download})

    # If the 'check_download' variable is True, start downloading the SSL certificate.
    if check_download:
        logger.debug("Starting to download the SSL Certificate files.")
        cert_control.download_multi(
            url=url, dest_path=path, files=cer_files.values())
        if service_name:
            svc.restart_service(service_name=service_name)
        return

    # Loadind the current certificate to compare expiration date with ssl certificate in
    # the server
    try:
        logger.info('Loading current certificate to verification')
        current_cert = cert_control.get_local_data(
            cert=open(f"{path}/{cer_files['cert']}", "rb").read())

    except ValueError as err:
        logger.error(str(err))
        logger.debug("Starting to download the SSL Certificate files.")
        cert_control.download_multi(
            url=url, dest_path=path, files=cer_files.values())
        if service_name:
            svc.restart_service(service_name=service_name)
        return

    try:
        logger.info('Loading SSL certificate from server for verification')
        new_cert = cert_control.get_remote_data(
            url=f"{url}/{cer_files['cert']}")
    except CertUrlException as err:
        logger.error(str(err))

    if current_cert.not_valid_after <= new_cert.not_valid_after:
        logger.info("Current SSL Certificate is valid")
        return

    logger.info("Updating SSL Certificate from this server")
    cert_control.download_multi(
        url=url, dest_path=path, files=cer_files.values())

    if service_name:
        svc.restart_service(service_name=service_name)


if __name__ == "__main__":
    logging.basicConfig(
        handlers=[RotatingFileHandler(
            './log/certificate_updater.log', maxBytes=100000, backupCount=10)],
        level=logging.DEBUG,
        format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
        datefmt='%Y-%m-%dT%H:%M:%S')

    logger = logging.getLogger(__name__)

    main()
