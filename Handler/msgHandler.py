import logging

logging.basicConfig(level=logging.INFO)

class info:

    def __init__(self,args):
        self.a = logging.info("Only one parameter can be selected from - v and - a.")
        self.b = logging.info("[+] 漏洞库暂不支持{}应用".format(args.software))

