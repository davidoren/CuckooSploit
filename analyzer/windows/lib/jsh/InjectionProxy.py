"""
This example builds on mitmproxy's base proxying infrastructure to
implement functionality similar to the "sticky cookies" option.
Heads Up: In the majority of cases, you want to use inline scripts.
"""
import os
from libmproxy import controller, proxy
from libmproxy.proxy.server import ProxyServer
from bs4 import BeautifulSoup
from libmproxy.protocol.http import decoded, HTTPResponse
from netlib.odict import ODictCaseless

class InjectionProxy(controller.Master):
    INJECT_BY_TAG = False
    JS_SERVING_PROXY_PORT = 8889
    cwd = os.path.dirname(os.path.realpath(__file__))
    #PATH = os.path.join(cwd, "JavaScriptHooks_new_arch.js")
    log = ""

    def get_logs(self):
        return self.log

    def __init__(self, server):
        controller.Master.__init__(self, server)

    def run(self):
        try:
            with open(os.path.join(self.cwd, "JavaScriptHooks_new_arch.js"), 'r') as f:
                self.script = f.read()
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, flow):
        if flow.request.headers['LOG']:
            resp = HTTPResponse(
                [1, 1], 404, "Not Found",
                ODictCaseless([["Content-Type", "text/html"]]),
                "Caught by proxy"
            )
            self.log += flow.request.content + "\r\n"
            flow.reply(resp)
        else:
            flow.reply()

    def handle_response(self, flow):
        if flow.response.code == 200:
            # avoid decoding into .js files (beautifulSoup has a bug that encode HTML chars
            # so for example 'if bla && bla' becomes 'if bla &amp;&amp; bla')
            if (flow.response.headers['Content-Type']) and (len(flow.response.headers['Content-Type']) != 0):
                if not 'application/javascript' == flow.response.headers['Content-Type'][0]:
                    with decoded(flow.response):  # Remove content encoding (gzip, ...)
                        html = BeautifulSoup(flow.response.content)
                        if html.body:
                            #javascript = html.new_tag("script", src="http://127.0.0.1:8889/JavaScriptHooks_new_arch.js")
                            javascript = html.new_tag("script")
                            if self.INJECT_BY_TAG:
                                javascript["src"] = "http://127.0.0.1:" + str(JS_SERVING_PROXY_PORT) + "/JavaScriptHooks_new_arch.js"
                            else:
                                javascript.string = self.script
                            html.body.insert(0, javascript)
                            flow.response.content = str(html)
                            print "JavaScript Functions Hooked.\n"
        flow.reply()


#config = proxy.ProxyConfig(port=8888)
#server = ProxyServer(config)
#m = InjectionProxy(server)
#print "Serving Proxy on port: 8888"
#m.run()
