import argparse
import logging
import logging.config
import os

from components.cert_manager import CertificateManager, CertUrlException
from components.service_manager import ServiceManager


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--dest_path",
                        help="SSL Certificate destination path.",
                        default="/etc/ssl/certs")
    parser.add_argument("-u", "--url",
                        help="args.url base to SSL Certificate download.",
                        default="https://i216.ffpadovani.tech")
    parser.add_argument("-c", "--cert_name",
                        help="Certificate file name.", default="fullchain.pem")
    parser.add_argument("-k", "--key_name",
                        help="Key file name", default="privkey.pem")
    parser.add_argument("-s", "--service",
                        help="Service name to be restarted.")
    args = parser.parse_args()

    cert_files = {"cert": args.cert_name, "key": args.key_name}
    cert_control = CertificateManager()
    svc = ServiceManager()

    logger.info("####  Starting certificate updater  ####")
    logger.debug("Loadins files in '%s' from verification.", args.dest_path)

    # Listing all SSL certificates installed on the server
    local_cert_list = os.listdir(path=args.dest_path)

    logger.debug("Checking if files 'fullchain.pem' and 'privkey.pem' exist")

    # Verifying that SSL certificate exist on the server

    check_files = dict(map(lambda x: (x, True) if x in local_cert_list else (
        x, False), cert_files.values()))

    check_download = False

    # Checking if the files exist, if one of them does not exist the variable
    # 'check_download' is changed to True
    for key, value in check_files.items():
        if not value:
            logger.info("%s/%s not found", args.dest_path, key)
            check_download = True
            logger.debug({"check_download": check_download})

    # If the 'check_download' variable is True, start downloading the SSL certificate.
    if check_download:
        logger.debug("Starting to download the SSL Certificate files.")
        cert_control.download_multi(
            url=args.url, dest_path=args.dest_path, files=cert_files.values())
        if args.service:
            svc.restart_service(service_name=args.service)
        return

    # Loadind the current certificate to compare expiration date with ssl certificate in
    # the server
    try:
        logger.info('Loading current certificate to verification')
        current_cert = cert_control.get_local_data(
            cert=open(f"{args.dest_path}/{cert_files['cert']}", "rb").read())

    except ValueError as err:
        logger.error(str(err))
        logger.debug("Starting to download the SSL Certificate files.")
        cert_control.download_multi(
            url=args.url, dest_path=args.dest_path, files=cert_files.values())
        if args.service:
            svc.restart_service(service_name=args.service)
        return

    try:
        logger.info('Loading SSL certificate from server for verification')
        new_cert = cert_control.get_remote_data(
            url=f"{args.url}/{cert_files['cert']}")
    except CertUrlException as err:
        logger.error(str(err))

    if current_cert.not_valid_after <= new_cert.not_valid_after:
        logger.info("Current SSL Certificate is valid")
        return

    logger.info("Updating SSL Certificate from this server")
    cert_control.download_multi(
        url=args.url, dest_path=args.dest_path, files=cert_files.values())

    if args.service:
        svc.restart_service(service_name=args.service)


if __name__ == "__main__":
    logging.config.fileConfig("logging.conf")
    logger = logging.getLogger(__name__)

    main()
