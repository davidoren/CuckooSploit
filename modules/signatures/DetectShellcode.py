import subprocess

from lib.cuckoo.common.abstracts import Signature
from subprocess import Popen, PIPE

class DetectShellcode(Signature):
    name = "detect_shellcode"
    description = "Shellcode detected using engine_cli"
    severity = 3
    categories = ["exploit", "rop"]
    authors = ["Ilana Marcus"]
    minimum = "1.2"
    evented = True
    enabled = True
    def __init__(self, caller):
        Signature.__init__(self, caller)
        filter_categories = set(["process"])
        
    def on_complete(self):
        if self.get_results("scd", {})["has_shellcode"]:
            return True
        return None
            

