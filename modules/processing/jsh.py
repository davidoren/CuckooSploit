# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from subprocess import Popen, PIPE


class jsh(Processing):

    order = 2

    def run(self):
        """Run analysis.
        @return: list of files with results.
        """
        self.key = "jsh"
        results = {}
        results['has_jsh_log'] = True
        results['output'] = []
        if os.path.exists(os.path.join(self.dropped_path, 'proxyLog.log')):
            with open(os.path.join(self.dropped_path, 'proxyLog.log'), 'r+') as f:
                data = f.readlines();

            for line in data:
                results['output'].append(line)

        return results;
