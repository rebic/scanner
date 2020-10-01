# -*- coding: utf-8 -*-
from publicScan import *
from createXLS import *
import os

NAME, VERSION, AUTHOR, LICENSE = "Public Monitor", "V0.1", "咚咚呛", "Public (FREE)"


def main(conf_info, syspath):
    """
    1.读取ip或host资产信息： 读文件
    2.读取常用端口
    3.nmap配置参数
    4.开始扫描
    """
    conf_info['result_info'] = []
    conf_info['change_add_list'] = []
    conf_info['change_del_list'] = []
    conf_info['weakpass_result'] = []
    conf_info['xlsfile'] = ""

    if not os.path.exists(syspath + '/out'):
        os.mkdir(syspath + '/out')
    if not os.path.exists(syspath + '/log'):
        os.mkdir(syspath + '/log')
    if not os.path.exists(syspath + '/tmp'):
        os.mkdir(syspath + '/tmp')

    pscan = PublicScan(conf_info['ip_file'], syspath)
    conf_info['result_info'], conf_info['change_add_list'], conf_info['change_del_list'] = pscan.run()

    if conf_info['result_info']:
        conf_info['xlsfile'] = Create_Xls(conf_info, syspath).run()
