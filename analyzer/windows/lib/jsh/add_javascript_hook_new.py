from bs4 import BeautifulSoup
from libmproxy.protocol.http import decoded
import os;

def start(context, argv):
    curdir = os.path.dirname(os.path.realpath('__file__'))
    with open(curdir + "\\JavaScriptHooks_new_arch.js", "r") as f:
        js = f.read()
        context.js = js

def response(context, flow):
    with decoded(flow.response):  # Remove content encoding (gzip, ...)
        html = BeautifulSoup(flow.response.content)
        if html.body:
            #print "This is the js:\n" + context.js
            javascript = html.new_tag("script")
            javascript.string = context.js
            html.body.insert(0, javascript)
            flow.response.content = str(html)
            context.log("Hooked JavaScript Functions.")