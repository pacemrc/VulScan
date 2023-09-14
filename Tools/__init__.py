import importlib
import os
import logging
from payload import payloadDir

dataDir = os.getcwd() + "\\data\\"


def instantiate_module_classes(package_name):

    modules = []

    # 导入包下的所有模块
    for module_file in os.listdir(payloadDir):
        if module_file.endswith(".py") and not module_file.startswith("__"):
            module_name = module_file.replace(".py", "")
            module = importlib.import_module(f"{package_name}.{module_name}")
            modules.append(module)

    # 实例化每个模块下的所有类
    classes = []
    for module in modules:
        for name, obj in module.__dict__.items():
            if isinstance(obj, type):
                classes.append(obj)

    instances = []
    for cls in classes:
        instances.append(cls())

    return instances

instances = instantiate_module_classes("payload")

software_list = []
allvul_list = []
for instance in instances:
    software_list = software_list + instance.software
    allvul_list = allvul_list + instance.vul_list




