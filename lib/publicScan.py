# -*- coding: utf-8 -*-
import os, json, nmap, re
from Log import *

NAME, VERSION, AUTHOR, LICENSE = "Public Monitor", "V0.1", "咚咚呛", "Public (FREE)"


class PublicScan:
    def __init__(self, file, syspath=""):
        self.syspath = syspath
        self.file = file
        self.result_info, self.change_del_list, self.change_add_list, self.measscan_result = [], [], [], []

    def Public_nmap(self, ipinfo=None):
        scanner = nmap.PortScanner()
        port = 80
        scanner.scan(path=self.file, arguments='-sS -T4 -p %d' % port)
        for targethost in scanner.all_hosts():
            for proto in scanner[targethost].all_protocols():
                lport = scanner[targethost][proto].keys()
                lport.sort()
                for port in lport:
                    if scanner[targethost][proto][port]['state'] == 'open':
                        temp = {}
                        temp['ip'] = targethost
                        temp['port'] = port
                        temp['server'] = scanner[targethost][proto][port]['name']
                        temp['state'] = 'open'
                        temp['protocol'] = proto
                        temp['product'] = scanner[targethost][proto][port]['product']
                        temp['product_version'] = scanner[targethost][proto][port]['version']
                        temp['product_extrainfo'] = scanner[targethost][proto][port]['extrainfo']
                        temp['reason'] = scanner[targethost][proto][port]['reason']
                        self.result_info.append("%s:%s:%s" % (temp['ip'], temp['port'], temp['server']))


    def diff(self):
        if os.path.exists(self.syspath + '/out/Result.txt'):
            oldlist = []
            with open(self.syspath + '/out/Result.txt') as f:
                for line in f:
                    oldlist.append(line.strip())
            old_change_list = list(set(oldlist).difference(set(self.result_info)))
            if old_change_list:
                self.Public_nmap(old_change_list)
                self.change_del_list = list(set(oldlist).difference(set(self.result_info)))
            self.change_add_list = list(set(self.result_info).difference(set(oldlist)))

    def callback(self):
        if not os.path.exists(self.syspath + '/out'):
            os.mkdir(self.syspath + '/out')
        fl = open(self.syspath + '/out/Result.txt', 'w')
        for i in self.result_info:
            fl.write(i)
            fl.write("\n")
        fl.close()

    def run(self):
        logger = LogInfo(self.syspath + '/log/process.log')
        logger.infostring('get ip list')

        logger.infostring('start nmap scan service...')
        self.Public_nmap()
        logger.infostring('finsh nmap scan.')

        logger.infostring('compare with the last result')
        self.diff()

        logger.infostring('generate the result file')
        self.callback()
        return self.result_info, self.change_add_list, self.change_del_list
