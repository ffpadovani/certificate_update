import logging


class ServiceManager:
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def restart_service(self, service_name):
        self.logger.info("Reiniciando serviço '%s'", service_name)
