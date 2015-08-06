import subprocess
import re
import os

from lib.cuckoo.common.abstracts import Processing
import logging
log = logging.getLogger(__name__)

class captipper(Processing):
    """Runs CapTipper on pcap"""

    def run(self):
        """Run CapTipper
        @return: CapTipper Struct
        """
        self.key = "captipper"
        strings = []
        PCAP_MAGIC = "\xd4\xc3\xb2\xa1"
        CAPTIPPER = "/home/tools/captipper/CapTipper.py"
        # If the analyzed file is a PCAP, run CapTipper on it, else run it on the dump.pcap file
        PCAPFILE = self.file_path if open(self.file_path, 'rb').read(4) == PCAP_MAGIC else self.pcap_path#/home/webmu/cuckoo/storage/analyses/latest/dump.pcap"
        log.info(PCAPFILE)
        REG_STR = "Magic: (.*)\)"

        #newpath = r'/home/webmu/cuckoo/storage/analyses/latest/files/captipper/'
        #newpath = r'/tmp/captipper/'
        newpath = self.dropped_path + '/captipper/'
        if not os.path.exists(newpath): 
            os.makedirs(newpath)

        regex = re.compile(REG_STR)
        CTout = subprocess.check_output(["sudo", "python", CAPTIPPER, PCAPFILE,'-d',newpath])
        types = regex.findall(CTout)

        exe_magic = False
        if "EXE" in types:
            exe_magic = True

        return dict(
            exe_exists=exe_magic
        )
