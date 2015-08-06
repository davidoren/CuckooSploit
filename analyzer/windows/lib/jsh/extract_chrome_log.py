import re

log_numbers = []

# This will parse chrome log, if something is changed than
# function will have to be changed as well
# this is looking for something like this "CONSOLE(<log_number>).*(<log_number>)"
def parse_chrome_list_by_log_number(log_number):
    if log_number in log_numbers: 
        return
    
    results = re.findall('CONSOLE\(' + log_number + '\)\].*\(' + log_number + '\)', data, re.IGNORECASE | re.DOTALL)
    results = results[0].split("[")
    #print str(results) + "\r\n-------------------------------------------------\r\n"
    results = re.search("\".*\"", results[0], re.IGNORECASE | re.DOTALL).group(0)[1:-1]
    print results
    
# in order for this to work we have to run Chrome with --enable-logging --v=1 cmd params
file_path = r'C:\Users\lab\AppData\Local\Google\Chrome\User Data\chrome_debug.log'
with open(file_path, 'r') as f:
    data = f.read()

match = re.findall('CONSOLE\(\d+\)\]', data, re.IGNORECASE)
for m in match:
    si = m.index("(")
    ei = m.index(")", si + 1)
    log_number = m[si+1:ei]
    parse_chrome_list_by_log_number(log_number)
    log_numbers.append(log_number)