from Tools import instances, software_list, allvul_list


def printDBInfo():

    print("-" * 100)
    print("{:<28s} {:<50s}".format("应用名称","漏洞编号"))

    for instance in instances:
        print("{:<30s} {:<50s}".format(str(instance.software),str(instance.vul_list).replace("[]'","")))
    print("-"*100)
    print("{:<28s}".format( "应用列表"))
    print("{:<30s}".format(str(software_list)))
    print("-"*100)
    print("{:<28s} {:<28s}".format("应用数量","漏洞数量"))
    print("{:<30d} {:<30d}".format(len(software_list),len(allvul_list)))


