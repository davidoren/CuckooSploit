# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
import subprocess
import os
import time
from libmproxy import proxy
from libmproxy.proxy.server import ProxyServer
import thread
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "lib", "jsh"))
import InjectionProxy
from lib.common.results import NetlogFile
import logging

log = logging.getLogger(__name__)

class ie_jsh(Package):
    """Internet Explorer analysis package."""
    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    working_path = ""

    def start(self, url):
        log.info("before proxy")
        config = proxy.ProxyConfig(port=8888)
        server = ProxyServer(config)
        self.m = InjectionProxy.InjectionProxy(server)
        log.info("before thread")
        thread.start_new_thread(self.m.run,())
        
        #self.working_path = os.path.dirname(os.path.realpath(__file__))
        #self.working_path = os.path.join(self.working_path, "..", "..", "lib", "jsh")
        #subprocess.Popen("python " + os.path.join(self.working_path, "InjectionProxy.py"))
        time.sleep(2) # waits for proxy to go up
        iexplore = self.get_path("Internet Explorer")
        log.info("after thread, before execute")
        return self.execute(iexplore, args="%s" % url)

    #def check(self):
        #data = self.m.get_logs()
        #nc = NetlogFile("files/proxyLog.log")
        #nc.send(data, retry=True)
        #return True

    def finish(self):
        data = self.m.get_logs()
        nc = NetlogFile("files/proxyLog.log")
        nc.send(data, retry=True)
        return True
