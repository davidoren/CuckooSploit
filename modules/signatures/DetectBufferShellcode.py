import subprocess

from lib.cuckoo.common.abstracts import Signature
from subprocess import Popen, PIPE


class DetectBufferShellcode(Signature):
    name = "detect_buffer_shellcode"
    description = "Found shellcode in a buffer."
    severity = 1
    categories = ["exploit", "rop"]
    authors = ["Ilana Marcus"]
    minimum = "1.2"
    evented = True
    enabled = True
    def __init__(self, caller):
        Signature.__init__(self, caller)
        self.buffers = []
        filter_categories = set(["process"])
        #filter_apinames = set(["LdrGetDllHandle", "WriteProcessMemory", "NtWriteVirtualMemory"])
        
    def decode_buffer(self, s):
        out = ''
        i = 0
        while i < len(s):
            try: 
                if i<len(s)-3:
                    if s[i:i+2] == '\\x':
                        out = out + s[i:i+4].decode('string_escape')
                        i = i + 4
                    else:
                        out = out + s[i]
                        i = i + 1
                else:
                    out = out + s[i]
                    i = i + 1
            except:
                #print("Error: " + s[i:])
                break
        return out
        
    def on_call(self, call, pid):
        if call["api"] in ["WriteProcessMemory", "memcpy", "NtWriteVirtualMemory"]:
            self.buffers.append(self.get_argument(call, "Buffer"))
            

    def on_complete(self):
        if len(self.buffers) > 0:
            with open("WPM_buffer_output.txt", 'wb') as output:
               for b in self.buffers:
                    try:
                        output.write(b.decode("string_escape"))
                    except:
                        output.write(self.decode_buffer(b))
            p = Popen(['/home/tools/scd/engine_cli', "WPM_buffer_output.txt"], stdout=PIPE, stderr=subprocess.STDOUT)
            engine_cli_output, err = p.communicate()
            if "SUPER-GREEN" in engine_cli_output:
                return True
        return False


