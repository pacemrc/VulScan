import argparse
import inspect
import ipaddress
import logging
import re
import socket

from urllib.parse import urlparse

from Handler import msgHandler
from Tools import instances, allvul_list, software_list



def getArgsParse():

    parser = argparse.ArgumentParser(usage="python vulscan.py [options]",add_help=False)

    target = parser.add_argument_group("Target")
    target.add_argument("-u",dest="url",type=str,help="input the target url")
    target.add_argument("-f",dest="urlfile",metavar="file",type=str,help="input urls from a file")

    scantype = parser.add_argument_group("ScanType")
    scantype.add_argument("-v",dest="vulid",metavar="vulid",type=str,help="vul id")
    scantype.add_argument("-a",dest="software",metavar="appname",type=str,help="the type of software")

    general = parser.add_argument_group("General")
    general.add_argument("-h","--help",action="help",help="show this help message and exit")
    general.add_argument("-p",metavar="proxy",type=str,help="proxy address")
    general.add_argument("--version",action="store_true",help="print version info")
    general.add_argument("--list",action="store_false",help="print all the vul")
    general.add_argument("--search",type=str,metavar="vulid",nargs="+",help="judge vul whether in vuldb")

    example = parser.add_argument_group("Example")
    example.add_argument(action="store_false",
                         dest="python vulscan.py -u http://127.0.0.1:8080 -v CVE-2021-44228\n"
                                                   "python vulscan.py -u http://127.0.0.1:8080 -v CVE-2020-1111,CVE-2020-2222\n"
                                                   "python vulscan.py -f D:\\tmp\\urls.txt -v CVE-2020-1234\n"
                                                   "python vulscan.py -f D:\\tmp\\urls.txt -a weblogic,jboss\n"
                                                   "python vulscan.py -u http://127.0.0.1:8080 -a all")

    args = parser.parse_args()

    return args

def argsControl(args):
    '''
        判断URL的逻辑
        '''


    url = args.url
    urlfile = args.urlfile
    url_list = []
    methodObj_list = []

    if url and urlfile: exit(0)
    if url and not urlfile:

        url_list.append(url)
    if urlfile and not url:
        with open(urlfile, "r", encoding="utf8") as f:
            url_list = [line.strip() for line in f.readlines()]

    '''
    判断扫描类型的逻辑
    '''

    if args.software and args.vulid:
        msgHandler.a
        exit(0)
    if args.software == "all":
        methodObj_list = getAllMethods()
    elif args.software != None:
        if isSoftExist(args.software):
            methodObj_list = getSoftWareAllMethods(args.software)
        else:
            msgHandler.getPrint(args)

    if args.vulid:
        vulid = args.vulid.strip(",")
        if vulid.find(","):
            vulid_list = vulid.split(",")
            if isVulExist(vulid_list):

                for vul_id in vulid_list:
                    methodObj = getVulIDMethod(vul_id)
                    methodObj_list.append(methodObj)
            else:

                logging.info("[+] 漏洞库暂无{}的POC".format(args.vulid))

    return url_list, methodObj_list


def getVulIDMethod(vul_id):

    vul_id = vul_id.lower().replace("-", "_")

    for instance in instances:

        methodName_list = [method[0] for method in inspect.getmembers(instance, predicate=inspect.ismethod) if
                   not method[0].startswith("__")]
        for methodName in methodName_list:
            if re.search(vul_id, methodName):
                methodObj = getattr(instance, methodName)

                return methodObj


def getSoftWareAllMethods(softname):

    softname = softname.lower()
    software_methodObj_list = []
    for instance in instances:
        instance_name = instance.__class__.__name__.lower()

        if re.search(softname,instance_name):
            methodName_list = [method[0] for method in inspect.getmembers(instance, predicate=inspect.ismethod) if
               not method[0].startswith("__")]

            for methodName in methodName_list:
                methodObj = getattr(instance, methodName)
                software_methodObj_list.append(methodObj)
            return software_methodObj_list


def getAllMethods():

    all_methodObj_list = []
    per_methodObj_list = []
    for instance in instances:
        methodName_list = [method[0] for method in inspect.getmembers(instance, predicate=inspect.ismethod) if
           not method[0].startswith("__")]
        for methodName in methodName_list:
            methodObj = getattr(instance, methodName)
            all_methodObj_list.append(methodObj)

        all_methodObj_list = per_methodObj_list + all_methodObj_list

    return all_methodObj_list


def isVulExist(vul_id):

    for vulid in vul_id:
        if vulid in allvul_list:
            return True

        return False


def isSoftExist(softname):
    softname = softname.strip(",")
    if softname.find(","):
        softname_list = softname.split(",")
    softname_list1 = [softname.lower() for softname in softname_list]
    software_list1 = [software.lower().replace(" ", "") for software in software_list]

    for softname in softname_list1:
        if re.search(softname, str(software_list1)):
            return True

    return False


def isSurvival(host,port):

    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((host,port))
        return True
    except:
        logging.info(f"Remote server {host}:{port} connection timeout")
        return False


def isValidUrl(url):

    urlObj = urlparse(url,scheme="http")
    if urlObj.scheme and urlObj.netloc:
        host = urlObj.hostname
        port = urlObj.port
        if ipaddress.ip_address(host):
            if isSurvival(host,port):
                return True
