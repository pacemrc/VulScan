import concurrent.futures
from Tools.common import isValidUrl,argsControl
from Tools import exploit, common


if __name__ == '__main__':

    args = common.getArgsParse()
    url_list, method_list = argsControl(args)


    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        for url in url_list:
            if isValidUrl(url):
                executor.submit(exploit.scan, url, method_list)

