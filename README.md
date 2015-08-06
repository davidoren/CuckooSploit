CuckooSploit
===============
Contributed By Check Point Software Technologies LTD.

CuckooSploit is an environment for comprehensive, automated analysis of web-based exploits, based on Cuckoo sandbox. 

The framework accepts URL or a PCAP file, and works at three levels:

Exploitation Process - Detecting the core components of the exploitation process (ROP chains, shellcodes, and heap sprays) for when exploitation takes place but fails to launch payload for several reasons, along with immediate successful post-exploitation phenomena (example, process creation).

Full Flow Emulation - Implementing the approach of full web emulation, rather than emulation of a single file at a time, since many exploits served by Exploit Kits do not work out of the web-page context (require configurations and/or arguments).

Web Flow Detection Redirection sequence chains, JavaScript obfuscations, evasion techniques.

By using full web emulation on different combinations of OS/browser/plugin version, CuckooSploit increases the rate of malicious URL detection and presents a reliable verdict and, in some cases, CVE identification.

### Installation

CuckooSploit is built upon the [Cuckoo Sandbox](https://github.com/cuckoobox/cuckoo), so all the pre-requisites and configurations must be made according to the [Cuckoo installation guide](http://docs.cuckoosandbox.org/en/latest/installation/).


For enabling PCAP emulation using [CapTipper](https://github.com/omriher/CapTipper), see the following instructions:

1. Install all prerequisites for Cuckoo Sandbox. We always used Ubuntu (both client and server) as nest and Windows XP/7 SP1 as guest machines (both x86/x64)
2. A Windows 7 guest machine should have UAC disabled
3. The Microsoft Loopback Adapter should be installed for the PCAP analysis package:
    1. Start -> CMD -> hdwwiz -> Next
    2. Install the hardware that I manually select from a list
    3. Network adapters
    4. Choose Microsoft as manufacturer and Microsoft Loopback Adapter as network adapter
    5. Next -> Next -> Finish

VM configuration for Javascript Hooking:

1. Python should be installed (pre-requisite for Cuckoo anyway).
2. Python.exe must be included in the PATH environment.
3. Install mitmproxy (pip install mitmproxy)
4. Install beautifulSoup (pip install beautifulsoup4)
5. Configure proxy settings in Internet Options to 127.0.0.1 on port 8888
6. Add "<-loopback>" (without quotation marks) to the Exceptions (in the proxy configurations)
6. Snapshot the VM


### Authors
 - [David Oren](mailto:davido@checkpoint.com) @davidoren26
 - [Liran Englender](mailto:lirane@checkpoint.com) @liraneng
 - [Omri Herscovici](mailto:omriher@gmail.com) @omriher
 - [Ilana Marcus](mailto:ilanam@checkpoint.com)
