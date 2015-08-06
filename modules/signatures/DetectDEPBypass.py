import subprocess

from lib.cuckoo.common.abstracts import Signature
from subprocess import Popen, PIPE

class DetectDEPBypass(Signature):
    name = "detect_dep_bypass"
    description = "Detects a DEP bypass"
    severity = 1
    categories = ["exploit", "rop"]
    authors = ["Ilana Marcus"]
    minimum = "1.2"
    evented = True
    enabled = True
    def __init__(self, caller):
        Signature.__init__(self, caller)
        filter_categories = set(["process"])
        self.has_dep_bypass = False
        self.api_call_functions = set()
        
    def on_call(self, call, pid):
        if call["api"] in ["NtAllocateVirtualMemory", "NtCreateFile", "WriteProcessMemory", "NtProtectVirtualMemory", "VirtualProtectEx", "NtWriteVirtualMemory", "memcpy"]:
            if self.get_argument(call, "DEPBypass") in ["1", 1]:
                self.has_dep_bypass = True
                self.api_call_functions.add(call["api"])
            

    def on_complete(self):
        if self.has_dep_bypass:
            self.description += ": {0}".format(self.api_call_functions)
            return True
        return False
