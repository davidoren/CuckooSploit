import re
from lib.cuckoo.common.abstracts import Signature

class CreatesProc(Signature):
    name = "creates_process"
    description = "Created processes: {0}"
    severity = 3
    categories = ["execution"]
    authors = ["Omri Herscovici", "Ilana Marcus"]
    minimum = "1.2"
    
    evented = True
    enabled = True

    def __init__(self, caller):
        Signature.__init__(self, caller)
        self.proc=[]

    def on_call(self, call, pid):
    	if (call["api"] != "CreateProcessInternalW"):
            return

        if re.search("iexplore", self.get_argument(call, "CommandLine"), re.IGNORECASE):
            return

        prc_name = self.get_argument(call, "CommandLine")
        self.proc.append(prc_name)
    

    def on_complete(self):
        if self.proc:
            self.description = self.description.format(', '.join(self.proc))
            return True



