import logging
import os


class ServiceManager:
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def restart_service(self, service_name):
        self.logger.info("Reiniciando serviço '%s'", service_name)
        try:
            os.popen("sudo systemctl start {service_name}")
            self.logger.info("{service_name} service started successfully...")
        
        except OSError as ose:
            self.logger.error("Error while running the command", ose)
