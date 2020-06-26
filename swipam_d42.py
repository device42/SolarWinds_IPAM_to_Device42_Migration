#!/usr/bin/env python
import sys
import os
import json
import base64
import ConfigParser
import threading
import Queue
import time

import requests

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass


CURRENT_DIR     =  os.path.dirname(os.path.abspath(__file__))
CONFIG          =  os.path.join(CURRENT_DIR,'settings.conf')


class Device42():
    def __init__(self, d42_server, d42_user, d42_secret, debug, hdevice, hlabel):

        self.base_url   = d42_server
        self.username   = d42_user
        self.password   = d42_secret
        self.debug      = debug
        self.hdevice    = hdevice
        self.hlabel     = hlabel

    def uploader(self, data, url):
        payload = data
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(self.username + ':' + self.password),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        r = requests.post(url, data=payload, headers=headers, verify=False)
        msg = unicode(payload)
        msgpayload = '\t[*] POST payload: %s' % msg
        if self.debug:
            print msgpayload

        msgstatus = '\t[+] Status code: %s' % str(r.status_code)
        if self.debug:
            print msgstatus
        msg = str(r.text)
        msgtext = '\t[*] Response: %s' % msg
        if self.debug:
            print msgtext
        if r.status_code in (401, 403, 404, 500, 503):
            print msgtext
        return msg

    def post_subnet(self, data, subnet):
        url = self.base_url + '/api/1.0/subnets/'
        msg = '\r\n[!] Posting subnet %s ' % subnet
        print msg
        self.uploader(data, url)

    def post_ip(self, data):
        url = self.base_url + '/api/ip/'
        msg = '\r\n[!] Posting ip %s ' % data['ipaddress']
        print msg
        self.uploader(data, url)


class SwisClient():
    def __init__(self, hostname, username, password, filter_broadcast):
        self.url            = "%s:17778/SolarWinds/InformationService/v3/Json/" % (hostname)
        self.credentials    = (username, password)
        self.headers        = {'Content-Type': 'application/json'}
        self.include_broadcast         = filter_broadcast

    def get_data(self, payload=None):
        r = requests.request('POST', self.url + 'Query',
                             data=json.dumps(payload),
                             auth=self.credentials,
                             headers=self.headers,
                             verify=False)
        if r.status_code == 200:
            return r.json()

    def get_subnets(self):
        networks    = []
        results     = self.get_data({'query': 'SELECT address,cidr,friendlyname FROM IPAM.Subnet'})
        if results:
            for result in results['results']:
                data    = {}
                name    = result['friendlyname']
                cidr    = result['cidr']
                address = result['address']
                if address and address != '0.0.0.0':
                    data.update({'network': address})
                    data.update({'mask_bits': cidr})
                    data.update({'name': name})
                    if data not in networks:
                        networks.append(data)

            for network in networks:
                net = network['network']
                d42.post_subnet(network, net)

    def get_ips(self):
        results = self.get_data({'query': 'SELECT ipaddress, mac, status, dnsbackward FROM  IPAM.IPNode'})

        if results:
            q = Queue.Queue()
            for result in results['results']:
                data = {}
                ipaddress   = result['ipaddress']
                macaddress  = result['mac']
                status      = result['status']
                devicename  = result['dnsbackward']
                print ipaddress

                if not self.include_broadcast:
                    split_ip = ipaddress.split('.')
                    last_ip_range_digit = split_ip[3]

                    if last_ip_range_digit == '0' or last_ip_range_digit == '255':  # ip is broadcast ip
                        print 'ip address {} is broadcast address, skipping'.format(ipaddress)
                        continue

                data.update({'ipaddress': ipaddress})
                data.update({'macaddress': macaddress})
                if status == 2:
                    data.update({'available':'yes'})
                if status == 4:
                    data.update({'type':'reserved'})
                if devicename and devicename not in ('',' '):
                    if hdevice:
                        data.update({'device': devicename})
                    if hlabel:
                        data.update({'tag': devicename})
                q.put(data)
            while 1:
                if not q.empty():
                    tcount = threading.active_count()
                    if tcount < 20:
                        ip = q.get()
                        print ip
                        p = threading.Thread(target=d42.post_ip, args=(ip,) )
                        p.start()
                    else:
                        time.sleep(0.5)
                else:
                    tcount = threading.active_count()
                    while tcount > 1:
                        time.sleep(1)
                        tcount = threading.active_count()
                        msg =  'Waiting for threads to finish. Current thread count: %s' % str(tcount)
                        print msg
                    break

def read_settings():
    if not os.path.exists(CONFIG):
        print '\n[!] Error. Cannot find config file!\n'
        sys.exit()

    cc = ConfigParser.RawConfigParser()
    cc.readfp(open(CONFIG,"r"))

    sw_ipam_server  = cc.get('settings', 'sw_ipam_server')
    sw_ipam_user    = cc.get('settings', 'sw_ipam_user')
    sw_ipam_secret  = cc.get('settings', 'sw_ipam_secret')
    d42_server      = cc.get('settings', 'd42_server')
    d42_user        = cc.get('settings', 'd42_user')
    d42_secret      = cc.get('settings', 'd42_secret')
    migrate_subnets = cc.getboolean('settings', 'migrate_subnets')
    migrate_ips     = cc.getboolean('settings', 'migrate_ips')
    debug           = cc.getboolean('settings', 'debug')
    hdevice         = cc.getboolean('settings', 'send_hostname_as_device')
    hlabel          = cc.getboolean('settings', 'send_hostname_as_label')
    filter_broadcast = cc.getboolean('settings', 'include_broadcast_addresses')

    return sw_ipam_server,sw_ipam_user,sw_ipam_secret,d42_server,d42_user,d42_secret,\
           migrate_subnets, migrate_ips, debug, hdevice, hlabel, filter_broadcast


if __name__ == "__main__":
    sw_ipam_server,sw_ipam_user,sw_ipam_secret,d42_server,d42_user,d42_secret,\
    migrate_subnets, migrate_ips, debug, hdevice, hlabel, filter_broadcast = read_settings()

    d42     = Device42(d42_server, d42_user, d42_secret, debug, hdevice, hlabel)
    swis    = SwisClient(sw_ipam_server, sw_ipam_user, sw_ipam_secret, filter_broadcast)

    if migrate_subnets:
        print 'getting subnets'
        swis.get_subnets()
    if migrate_ips:
        print 'getting ips'
        swis.get_ips()

    print '\n[!] Done!'
    sys.exit()

