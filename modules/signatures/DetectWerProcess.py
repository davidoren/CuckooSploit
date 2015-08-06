import subprocess

from lib.cuckoo.common.abstracts import Signature
from subprocess import Popen, PIPE
import re

class DetectWerProcess(Signature):
    name = "detect_WerFault"
    description = "Detected a crash"
    severity = 2
    categories = ["exploit", "rop"]
    authors = ["Ilana Marcus"]
    minimum = "1.2"
    enabled = True
    def __init__(self, caller):
        Signature.__init__(self, caller)
        filter_categories = set(["process"])
        
    def on_complete(self):
        for proc in self.get_results("behavior", {})["processes"]:
            if proc["process_name"].lower() == "werfault.exe":
                return True
        for proc in self.get_results("running_processes", []):
            if proc["Caption"] == "WerFault.exe":
                pattern = re.compile("C:\\\\Windows\\\\system32\\\\WerFault.exe\s-u\s-p\s(\d+)\s-s\s\d+")
                
                command_line = proc["CommandLine"] #eg, C:\Windows\system32\WerFault.exe -u -p 3796 -s 612
                matches = pattern.match(command_line)
                
                if (matches):
                    if matches.group(1):
                        crashed_process_pid = matches.group(1)
                        crashed_process = self.get_process_by_pid(crashed_process_pid)
                        if crashed_process:
                            self.description += " in process {0} with pid {1}".format(crashed_process["Caption"], crashed_process["ProcessId"])
                return True
        return None 
            
    def get_process_by_pid(self, pid):
        for proc in self.get_results("running_processes", []):
            if proc["ProcessId"] == pid:
                return proc
