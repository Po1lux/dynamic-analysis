#!/usr/bin/env python

import tail
import re
import time
import urllib2
com0 = r'VPN_AUH'
com1 = r'(\d{2}:\d{2}:\d{2})[\s\S]*auth-(\w+)[\s\S]*user \'(\w+)\'[\s\S]*auth profile \'(\w+)\'[\s\S]*From: (\d+.\d+.\d+.\d+)'
pattern0 = re.compile(com0)
pattern1 = re.compile(com1)

ipInfo={}
denyConut =3
denyInterval = 120

def print_line(content):
    if re.search(pattern0,content)!= None:
        result = re.findall(pattern, content)
        name = result[0][2]
        ip = result[0][4]
        time = result[0][0]
        state = result[0][1]
        type = result[0][3]

        referIp = 'http://int.dpool.sina.com.cn/iplookup/iplookup.php?format=js&ip=%s' % ip
        h = urllib2.urlopen(referIp)
        html = h.read()
        location = re.findall('\"city\":\"(.*?)\"', html)
        cTime = time.time()
        dictObjInfo = {name:
                       {'loca': location,
                        'time': time,
                        'state': state,
                        'type': type,
                        'name': name,
                        'ip': ip
                        }}
        #login success
        if state == 'success':
            print dictObjInfo
            with open(r'./info.json','r') as f:
                info = json.load(f)
                #type(info[dictName]['loca'].encode("utf-8"))   unicode to str
                #type(''.join(dictObj[dictName]['loca']))       list to str
                if name in info.keys() and info[name]['loca'].encode("utf-8")!=''.join(location):
                    with open(r'./yidi.json','a+') as f:
                        yidiJson = json.dumps(dictObjInfo)
                        f.write(yidiJson)   #write suspicious json data into file yidi.json.


        #login failed
        if state == 'fail' and ip in ipInfo.keys():
            print 'fail1'
            ipInfo[ip]['tConut'] = ipInfo[ip]['tConut']+1
            #exist burte force attack
            if cTime-ipInfo[ip]['lTime'] < denyInterval and ipInfo[ip]['tCount'] > denyConut:
                with open(r'./deny.json','a+') as f:
                    denyJson = json.dumps(dictObjInfo)
                    f.write(denyJson)
            #update lTime
            elif cTime-ipInfo[ip]['lTime'] > denyInterval:
                ipInfo[ip]['lTime'] = cTime
        #update dictObjIp
        elif state == 'fail' and ip not in ipInfo.keys():
            print 'fail2'
            dictObjIp = {ip:
                             {
                                 'lTime':cTime,
                                 'count':tCount
                             }
            }
            ipInfo.update(dictObjIp)


t = tail.Tail('/var/log/syslog')
t.register_callback(print_line)
t.follow(s=2)


