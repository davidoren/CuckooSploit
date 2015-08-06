# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import subprocess
import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from subprocess import Popen, PIPE


class static_scd(Processing):
    """shellcode detector static analysis."""

    order = 2
    path_to_tools = "/home/tools"
    def search_for_hexas(self, pattern, data):
        matches = re.finditer(pattern, data)

        # we asked for iterator so we can't call matches[0].group(0)
        hexas = None
        for match in matches:
            hexas = match.group(0)
            break

        return hexas

    def has_ext(self, fl):        
        name, ext = os.path.splitext(fl)
	if ext != "":
            return True
        return False

    def run(self):
        """Run analysis.
        @return: list of files with results.
        """
        self.key = "scd"
        results = {}
        results["has_shellcode"] = False
        results["outputs"] = []
        dropped_files = []
        output_file_name = "output.txt"
        engine_cli_output = "None"
        jesus_output = "None"
        engine_cli_after_jesus_output = "None"
        engine_cli_hexdata = "None"

	# find all relevant files
        for dir_name, dir_names, file_names in os.walk(self.dropped_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                #file_info = File(file_path=file_path).get_all()

                if ('.html' in file_name) or ('.htm' in file_name) or ('.js' in file_name) or (not self.has_ext(file_path)):
                    # engine_cli
                    p = Popen([self.path_to_tools+'/scd/engine_cli', file_path], stdout=PIPE, stderr=subprocess.STDOUT)
                    engine_cli_output, err = p.communicate()

                    # JESUS + engine_cli
                    p = Popen(['java', '-jar', '/home/tools/jesus.jar', file_path], stdout=PIPE, stderr=PIPE)
                    jesus_output, err = p.communicate()
                    if err:
                        jesus_output = "ERROR"
                    else:
                        # engine_cli doesn't get input from stdin so we need to save
                        # the output from jesus to a file
                        with open('jesus_output', 'w+') as f:
                            f.write(jesus_output)

                        p = Popen([self.path_to_tools+'/scd/engine_cli', 'jesus_output'], stdout=PIPE, stderr=subprocess.STDOUT)
                        engine_cli_after_jesus_output, err = p.communicate()

                        # hex character search
                        min_repeat_number = 5

                        # i'm not sure why this is the only way it works (with finditer)
		                # looking for \x\d\d pattern'''
                        hexas = self.search_for_hexas('(\\\\x[0-9a-fA-F][0-9a-fA-F]){' + str(min_repeat_number) + ',}', jesus_output)
                        
                        # if there's no match for \x\d\d pattern, look for \d\d pattern
                        if not hexas:
                            hexas = self.search_for_hexas('([0-9a-fA-F][0-9a-fA-F]){' + str(min_repeat_number) + ',}', jesus_output)
                        
                        if hexas:
                            # create a list with \d\d in each cell
                            hexas = re.findall('[0-9a-fA-F][0-9a-fA-F]', hexas)
                            engine_cli_hexdata = ""
                            for h in hexas:
                                engine_cli_hexdata += h.decode('hex')

                            # engine_cli doesn't get input from stdin so we need to save
                            # the output to a file
                            with open('hexdata', 'w+') as f:
                                f.write(engine_cli_hexdata)

                            p = Popen([self.path_to_tools+'/scd/engine_cli', 'hexdata'], stdout=PIPE, stderr=subprocess.STDOUT)
                            engine_cli_hexdata, err = p.communicate()

                    #if any("SUPER-GREEN" in s for s in [engine_cli_output, engine_cli_after_jesus_output, engine_cli_hexdata]):
                    shellcode_flag = "SUPER-GREEN"
                    if shellcode_flag in engine_cli_output or shellcode_flag in engine_cli_after_jesus_output or shellcode_flag in engine_cli_hexdata:
                        results["outputs"].append({"file_name": file_name, "file_path": file_path, "engine_cli_output": engine_cli_output, "engine_cli_after_jesus_output": engine_cli_after_jesus_output, "engine_cli_hexdata": engine_cli_hexdata})
                        results["has_shellcode"] = True
        return results
