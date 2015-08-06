from lib.common.abstracts import Auxiliary
from lib.common.results import NetlogFile
import subprocess
import json

class Running_Processes(Auxiliary):
    def start(self):
        self.cmd = 'WMIC PROCESS get Caption,ProcessId,CommandLine /VALUE'
    
    def stop(self):
        all_running = []
        proc = subprocess.Popen(self.cmd, shell=True, stdout=subprocess.PIPE)
        
        processes = proc.stdout.read().split("\r\r\n\r\r\n")
        
        for p in processes:
            p = p.strip()
            parts = p.split("\r\r\n")
            
            proc_dict = {}
            for kv_pair in parts:
                try:
                    kv = kv_pair.split('=')
                    proc_dict[kv[0]] = kv[1]
                    all_running.append(proc_dict)
                except:
                    continue
        proc.terminate()
        
        nf = NetlogFile("logs/running_processes.log")
        nf.sock.sendall(json.dumps(all_running))
        nf.close()
