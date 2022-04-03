import os
from typing import List
from xmlrpc.client import boolean
import IPython
import subprocess
import logging
from dataclasses import dataclass
import threading
import tempfile
import xml.etree.ElementTree as ET

@dataclass
class TRResult:
    proc: threading.Thread
    lock: threading.Lock
    nodes: List

def nmap_thread(host: str, lock):
    with tempfile.TemporaryDirectory() as dir:
        xmlfile = os.path.join(dir, "nmap.xml")
        try:
            ret = subprocess.run(
                ["nmap", "-sn", "-Pn", "-oX", xmlfile, "--traceroute", host], 
                check=True,             # check process started OK 
                capture_output=True     # stop output going to stdout
                )
        except  subprocess.CalledProcessError as e:
            logging.exception(e)

        with lock:
            logging.info(f"Nmap to {host} has now finished with exit code {ret.returncode}")

            # parse the XML
            try:
                tree = ET.parse(xmlfile)
            except Exception as e:
                logging.exception(e)

            root = tree.getroot()

            """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE nmaprun>
            <?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
            <!-- Nmap 7.80 scan initiated Sat Apr  2 20:20:26 2022 as: nmap -sn -Pn -oX /tmp/tmpp946k4hi/nmap.xml -&#45;traceroute slashdot.org -->
            <nmaprun scanner="nmap" args="nmap -sn -Pn -oX /tmp/tmpp946k4hi/nmap.xml -&#45;traceroute slashdot.org" start="1648927226" startstr="Sat Apr  2 20:20:26 2022" version="7.80" xmloutputversion="1.04">
            <verbose level="0"/>
            <debugging level="0"/>
            <host starttime="0" endtime="0"><status state="up" reason="user-set" reason_ttl="0"/>
            <address addr="204.68.111.106" addrtype="ipv4"/>
            <hostnames>
            <hostname name="slashdot.org" type="user"/>
            </hostnames>
            <trace proto="icmp">
            <hop ttl="1" ipaddr="192.168.1.254" rtt="3.69" host="_gateway"/>
            <hop ttl="2" ipaddr="172.16.12.88" rtt="4.37"/>
            <hop ttl="4" ipaddr="62.172.102.68" rtt="8.28"/>
            <hop ttl="5" ipaddr="62.172.103.39" rtt="23.93" host="peer8-et0-0-6.telehouse.ukcore.bt.net"/>
            <hop ttl="6" ipaddr="195.99.126.233" rtt="11.11"/>
            <hop ttl="7" ipaddr="172.70.87.4" rtt="11.16"/>
            <hop ttl="8" ipaddr="172.70.84.152" rtt="8.06"/>
            <hop ttl="9" ipaddr="172.70.84.75" rtt="8.12"/>
            <hop ttl="10" ipaddr="172.70.84.127" rtt="7.81"/>
            <hop ttl="12" ipaddr="204.68.111.106" rtt="139.39"/>
            </trace>
            <times srtt="139389" rttvar="139389" to="696945"/>
            </host>
            <runstats><finished time="1648927229" timestr="Sat Apr  2 20:20:29 2022" elapsed="3.44" summary="Nmap done at Sat Apr  2 20:20:29 2022; 1 IP address (1 host up) scanned in 3.44 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
            </runstats>
            </nmaprun>
            """

            stdout = ret.stdout.decode(encoding="utf8", errors="replace")
            logging.debug(stdout)

def is_pending(res: threading.Thread) -> boolean:
    """
    """
    return res.is_alive()

def traceroute(host: str) -> TRResult:
    """
    """
    lock = threading.Lock()
    proc = threading.Thread(target=nmap_thread, args=(host,lock,))
    proc.start()

    res = TRResult(proc, lock, [])

    return res


FORMAT = '%(asctime)s : %(message)s'
logging.basicConfig(format=FORMAT, level=logging.DEBUG)
IPython.embed()