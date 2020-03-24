# -*- coding: utf-8 -*-
# @Time    : 2020-03-18 15:41
# @Author  : hahadaxia
# @Email   : yzujk0502@126.com

# import ssdc
import yara
import os

def get_file_path(root_path,file_list,dir_list):
    #获取该目录下所有的文件名称和目录名称
    dir_or_files = os.listdir(root_path)
    for dir_file in dir_or_files:
        #获取目录或者文件的路径
        dir_file_path = os.path.join(root_path,dir_file)
        #判断该路径为文件还是路径
        if os.path.isdir(dir_file_path):
            dir_list.append(dir_file_path)
            #递归获取所有文件和目录的路径
            get_file_path(dir_file_path,file_list,dir_list)
        else:
            # if dir_file_path.split('.')[-1] in []:
            file_list.append(dir_file_path)
    return file_list

#获取目录内的yara规则文件# 将yara规则编译
def getRules(path):
    filepath = {}
    for index,file in enumerate(os.listdir(path)):
        rupath = os.path.join(path, file)
        key = "rule"+str(index)
        filepath[key] = rupath
        yararule = yara.compile(filepaths=filepath)
    return yararule
# 扫描函数
def scan(rule, path):
    # for file in os.listdir(path):
    #     mapath = os.path.join(path, file)
    file_list = []
    #用来存放所有的目录路径
    dir_list = []
    for filepath in get_file_path(path,file_list,dir_list):
        fp = open(filepath, 'rb')
        matches = rule.match(data=fp.read())
        if len(matches)>0:
            print(filepath,matches)
if __name__ == '__main__':
    rulepath = "/Users/zzh/github/allwebshell/rules/webshells"
    #yara规则目录 
    # malpath ="/Users/zzh/github/allwebshell/WebShell2" # 木马存在目录 
    malpath = './samples'
    # yara规则编译函数调用 

    yararule = getRules(rulepath)
    #扫描函数调用 
    scan(yararule, malpath)


