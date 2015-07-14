#!/usr/bin/env python
import sys
import os
import json
import requests
import base64
import ConfigParser

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

    def post_ip(self, data, ip):
        url = self.base_url + '/api/ip/'
        msg = '\r\n[!] Posting ip %s ' % ip
        print msg
        self.uploader(data, url)


class SwisClient():
    def __init__(self, hostname, username, password):
        self.url            = "%s:17778/SolarWinds/InformationService/v3/Json/" % (hostname)
        self.credentials    = (username, password)
        self.headers        = {'Content-Type': 'application/json'}

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
        ips = []
        results = self.get_data({'query': 'SELECT ipaddress, mac, status, dhcpclientname FROM  IPAM.IPNode'})
        if results:
            for result in results['results']:
                data = {}
                ipaddress   = result['ipaddress']
                macaddress  = result['mac']
                status      = result['status']
                devicename  = result['dhcpclientname']
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

                ips.append(data)

            for ip in ips:
                address = ip['ipaddress']
                d42.post_ip(ip, address)


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

    return sw_ipam_server,sw_ipam_user,sw_ipam_secret,d42_server,d42_user,d42_secret,\
           migrate_subnets, migrate_ips, debug, hdevice, hlabel


if __name__ == "__main__":
    sw_ipam_server,sw_ipam_user,sw_ipam_secret,d42_server,d42_user,d42_secret,\
    migrate_subnets, migrate_ips, debug, hdevice, hlabel = read_settings()

    d42     = Device42(d42_server, d42_user, d42_secret, debug, hdevice, hlabel)
    swis    = SwisClient(sw_ipam_server, sw_ipam_user, sw_ipam_secret)

    if migrate_subnets:
        swis.get_subnets()
    if migrate_ips:
        swis.get_ips()

    print '\n[!] Done!'
    sys.exit()

