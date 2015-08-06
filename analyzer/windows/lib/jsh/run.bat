@echo [+] Running Server
@echo off
start python server.py 8889

@echo [+] Running MITMproxy
@echo off
start python "C:\Python27\scripts\mitmdump" -q -p 8888 -s "%cd%\add_javascript_hook.py" --anticache
