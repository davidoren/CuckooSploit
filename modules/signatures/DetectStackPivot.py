import subprocess

from lib.cuckoo.common.abstracts import Signature
from subprocess import Popen, PIPE

class DetectStackPivot(Signature):
    name = "detect_stack_pivot"
    description = "Detects a stack pivot"
    severity = 3
    categories = ["exploit", "rop"]
    authors = ["Ilana Marcus"]
    minimum = "1.2"
    evented = True
    enabled = True
    def __init__(self, caller):
        Signature.__init__(self, caller)
        filter_categories = set(["process"])
        self.has_stack_pivot = False
        self.api_call_functions = set()
        
    def on_call(self, call, pid):
        if call["api"] in ["NtCreateFile", "NtAllocateVirtualMemory", "WriteProcessMemory", "NtProtectVirtualMemory", "VirtualProtectEx", "NtWriteVirtualMemory", "memcpy", "CreateProcessInternalW", "URLDownloadToFileW", "CreateFileMappingW", "CreateFileMappingA"]:
            if self.get_argument(call, "StackPivoted") in ["1", 1]:
                self.has_stack_pivot = True
                self.api_call_functions.add(call["api"])
            

    def on_complete(self):
        if self.has_stack_pivot:
            self.description += ": {0}".format(self.api_call_functions)
            return True
        return False
