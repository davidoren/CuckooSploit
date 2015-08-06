# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import logging 
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
import json

log = logging.getLogger(__name__)

class RunningProcessesSnapshot(Processing):
    """General information about a file."""

    def run(self):
        """Run file information gathering.
        @return: information dict.
        """
        self.key = "running_processes"

        running_processes = []

        p_log = os.path.join(self.logs_path, "running_processes.log")
        try:
            with open(p_log, 'r') as file:
                running_processes = json.load(file)
        except Exception as e:
            log.warning("Error in RunningProcessesSnapshot module: %s", e)
        return running_processes