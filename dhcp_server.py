import logging as log
import sys

FORMAT = '[%(asctime)s] [%(levelname)s] : %(message)s'
log.basicConfig(stream=sys.stdout, level=log.DEBUG, format=FORMAT)


class DHCP_Server:
    def __init__(self):
        log.info("Starting server")

