import subprocess
import logging
import json
from lib.cuckoo.common.abstracts import Signature
from subprocess import Popen, PIPE
log = logging.getLogger(__name__)


class DetectDEPInHeap(Signature):
    name = "Detect DEP bypass in the heap, probably by ROP"
    description = "Detects DEP bypass in the heap"
    severity = 2
    categories = ["exploit", "rop"]
    authors = ["Ilana Marcus"]
    minimum = "1.2"
    evented = True
    enabled = True
    MEM_PRIVATE = 0x20000
    READ_WRITE_EXECUTE = 0x40
    
    def __init__(self, caller):
        Signature.__init__(self, caller)
        filter_categories = set(["process"])
        self.has_dep_bypass = False
        self.api_call_functions = set()
        self.hits = []
        
    def on_call(self, call, pid):
        if call["api"] in ["NtProtectVirtualMemory", "VirtualProtectEx", "VirtualAllocEx"]:
            if int(self.get_argument(call, "VirtQueryType")) == self.MEM_PRIVATE and \
                int(self.get_argument(call, "protection").replace("0x", ""), 16) == self.READ_WRITE_EXECUTE:
                
                self.has_dep_bypass = True
                self.api_call_functions.add(call["api"])
                
                address = self.get_argument(call, "BaseAddress")

                old_protection = int(self.get_argument(call, "old_protection").replace("0x", ""), 16)
                formatted_old_protection = format(old_protection, '02x')
                
                new_protection = int(self.get_argument(call, "protection").replace("0x", ""), 16)
                formatted_new_protection = format(new_protection, '02x')
                
                match_data = {"address": address, "old_protection": formatted_old_protection, "new_protection":formatted_new_protection}
                
                #self.add_match(None, "api", match_data)
                self.hits.append(match_data)

    def on_complete(self):
        if self.has_dep_bypass:
            self.description += ": {0}".format(self.api_call_functions)
            for hit in self.hits:
                self.description += " [address: {0}, old protection: {1}, new protection {2}] ".format(hit["address"], hit["old_protection"], hit["new_protection"])
            return True
        return False
