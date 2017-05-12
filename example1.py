#!/usr/bin/env python

import tail
import re
import time
import urllib2
import json

#com0 = r'VPN_AUTH'
comp = r'(\d{2}:\d{2}:\d{2})[\s\S]*auth-(\w+)[\s\S]*user \'(\w+)\'[\s\S]*auth profile \'(\w+)\'[\s\S]*From: (\d+.\d+.\d+.\d+)'
#com2 = r'\"(\w+) for user \'(\w+)\'[\s\S]*auth profile \'(\w+)\'[\s\S]*From: (\d+.\d+.\d+.\d+)'
pattern = re.compile(comp)
#pattern1 = re.compile(com2)

ipInfo={}
denyConut =1
denyInterval = 120

def print_line(content):
    if pattern.findall(content)!= None and len(pattern.findall(content))!=0:
        result = re.findall(pattern,content)
        name = result[0][2]
        ip = result[0][4]
        time = getCurrentTime()
        state = result[0][1]
        type = result[0][3]
        location = getLocation(ip)
        dictObjInfo = {name:
                       {'location': location,
                        'time': time,
                        'state': state,
                        'type': type,
                        'name': name,
                        'ip': ip
                        }}

        if state == 'success':
            judgeLocation(dictObjInfo)

        if state == 'fail':
            judgeForce(dictObjInfo)


def getLocation(ip):
    referIp = 'http://int.dpool.sina.com.cn/iplookup/iplookup.php?format=js&ip=%s' % ip
    h = urllib2.urlopen(referIp)
    html = h.read()
    location = re.findall('\"city\":\"(.*?)\"', html)
    return location

def getCurrentTime():
    x = time.localtime(time.time())
    ymd = time.strftime('%Y-%m-%d %H:%M:%S',x)
    return ymd



def judgeLocation(objInfo):
    name = objInfo[objInfo.keys()[0]]['name']
    location = objInfo[objInfo.keys()[0]]['location']

    with open(r'./info.json', 'r') as f:
        info = json.load(f)
        # type(info[dictName]['loca'].encode("utf-8"))   unicode to str
        # type(''.join(dictObj[dictName]['loca']))       list to str
        if name in info.keys() and info[name]['loca'].encode("utf-8") != ''.join(location):
            with open(r'./yidi.json', 'a+') as f:
                yidiJson = json.dumps(objInfo)
                f.write(yidiJson)  # write suspicious json data into file yidi.json.
                print 'exist suspicious location login'
                print objInfo



def judgeForce(objInfo):
    state = objInfo[objInfo.keys()[0]]['state']
    ip = objInfo[objInfo.keys()[0]]['ip']
    cTime = getCurrentTime()

    if ip in ipInfo.keys():
        ipInfo[ip]['tConut'] = ipInfo[ip]['tConut'] + 1
        # exist burte force attack
        if cTime - ipInfo[ip]['lTime'] < denyInterval and ipInfo[ip]['tCount'] > denyConut:
            with open(r'./deny.json', 'a+') as f:
                denyJson = json.dumps(objInfo)
                f.write(denyJson)
                print 'exist suspicious crack login'
                print objInfo
        # update lTime
        elif cTime - ipInfo[ip]['lTime'] > denyInterval:
            ipInfo[ip]['lTime'] = cTime
            ipInfo[ip]['tConut'] = 0

    # update dictObjIp
    elif ip not in ipInfo.keys():
        cTime = getCurrentTime()
        tCount= 1
        dictObjIp = {ip:
            {
                'lTime': cTime,
                'count': tCount
            }
        }
        ipInfo.update(dictObjIp)


t = tail.Tail('./var/log/messages')
t.register_callback(print_line)
t.follow(s=1)


