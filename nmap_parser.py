#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import logger

# TODO find elegant way to also include verbosity level here
# ? make logger part of the Pool class and use pool.logger.set_verbosity(3) from within recon4me ?
logger=logger.Logger(2)

class NmapParser():
    def __init__(self,inputfile):
        self.inputfile = inputfile
        logger.debug("using following xml file: {self.inputfile}")
    def get_open_ports(self):
        services = {}
        tree = ET.parse(self.inputfile)
        root = tree.getroot()
        for port in root.iter('port'):
            # if port is open, then add to service list
            if (port.find('state').attrib['state'] == 'open'):
                # port number
                portid = port.attrib['portid']
                # estimated service behind port
                service_name = port.find('service').attrib['name']
                services[portid]=service_name
        return services

    # TODO change get_open_ports to xml parser that starts on init 
    # TODO make variables like self.ports, self.services, self.names, self.scripts and get them via the class itself get_open_ports/services/names/... 


if __name__ == "__main__":
    inputfile = "/mnt/hgfs/VMshare/git/wrecon/35.186.165.146/scans/nmap_35.186.165.146.xml"
    nmapParser = NmapParser(inputfile)
    services = nmapParser.get_open_ports()
    print(services)
    for service in services:
        print(service)
        print(services[service])