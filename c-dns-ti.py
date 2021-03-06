# Author: Mirco Gentili
# Date 20170219
# Version: 0.2
# Description: Cyber DNS Threat Intelligence

from datetime import datetime
from datetime import timedelta
from elasticsearch import Elasticsearch
from elasticsearch import helpers
import ipaddress
import csv
import re


index_name = "packetbeat-*"
type_name = "dns"
size_count = 200
time_delta = "01:45:00"
host = "http://192.168.47.200:9200"
es = Elasticsearch([host], timeout=100)

# ricerca viene fatta nella modalità "last time_delta". Quindi dal momento in cui viene lanciato lo script - time_delta
time_end = datetime.now().replace(microsecond=0)
(h, m, s) = time_delta.split(':')
time_start = (time_end - timedelta(hours=int(h),minutes=int(m), seconds=int(s)))
time_start = int(time_start.timestamp()) * 1000
time_end = int(time_end.timestamp()) * 1000

regex_arpa_ip = r"(\d*)\.(\d*)\.(\d*)\.(\d*)"

dns_query_a = {
    "size": size_count,
    "_source": ["dns", "ip", "client_ip"],
     "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "dns.question.type": {
                            "query": "A",
                            "type": "phrase"
                        }
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "gte": time_start,
                            "lte": time_end,
                            "format": "epoch_millis",
                        }
                    }
                }
            ],
            "must_not": []
        }
    },

}

dns_query_ptr = {
    "size": size_count,
    "_source": ["dns", "ip", "client_ip", "resource"],
    "query": {
        "bool": {
            "must": [
                {
                    "match": {
                        "dns.question.type": {
                            "query": "PTR",
                            "type": "phrase"
                        }
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "gte": time_start,
                            "lte": time_end,
                            "format": "epoch_millis"
                        }
                    }
                }
            ],
            "must_not": []
        }
    }

}

print(datetime.now().replace(microsecond=0))

result_query_dns_a = helpers.scan(                 # modalità scan per non avere limiti sul numero max di risultati ritornati
    es, index=index_name, doc_type=type_name, query=dns_query_a)

dns_record = {}
list_dns_record = []

for k1 in result_query_dns_a:
    try:
        len_type_list = len(k1["_source"]["dns"]["answers"])
        for k2 in range(len_type_list):         # secondo ciclo for perchè a una singola answer possono corrispondere più valori A
            try:
                dns_type = k1["_source"]["dns"]["answers"][k2]["type"]  
                if dns_type == "A":
                    try:
                        ip_address = k1["_source"]["dns"]["answers"][k2]["data"]
                        client_ip = k1["_source"]["client_ip"]
                        name = k1["_source"]["dns"]["answers"][k2]["name"]
                        dns_server = k1["_source"]["ip"]
                        dns_record = {'ip_address': ip_address, "name": name, "dns_server": dns_server, "client_ip": client_ip}
                    except Exception as error:
                        pass
                    if not ipaddress.IPv4Address(ip_address).is_private and not dns_record in list_dns_record: 
                        list_dns_record.append(dns_record)
            except Exception as error:
                pass
    except Exception as error:
        pass

result_query_dns_ptr = helpers.scan(
    es, index=index_name, doc_type='dns', query=dns_query_ptr)

for k1 in result_query_dns_ptr:
    try:
        client_ip = k1["_source"]["client_ip"]
        dns_server = k1["_source"]["ip"]
        name = k1["_source"]["resource"]
        ip_address_arpa = k1["_source"]["dns"]["question"]["name"]
        list_oct_ip_address = list(re.findall(regex_arpa_ip, ip_address_arpa)).pop()[::-1]
        ip_address = str.join('.', list_oct_ip_address)
        dns_record = {'ip_address': ip_address, "name": name, "dns_server": dns_server, "client_ip": client_ip}
        if not ipaddress.IPv4Address(ip_address).is_private and not dns_record in list_dns_record:
            list_dns_record.append(dns_record)
    except Exception as error:
        pass

# lista_ip (no duplicati) degli indirizzi publici da controllare
list_ip = []
for k1 in list_dns_record:
    list_ip.append(k1['ip_address'])
list_ip = list(set(list_ip))

lutech_cti_list = []
lutech_cti_dict = {}
lutech_threat_feed_list = []
k_list = []

with open('dailyOutput.csv', encoding='utf-8') as csvfile:
    ctireader = csv.reader(csvfile, delimiter=',', quotechar='"')
    lutech_cti_list = list(ctireader)

len_lutech_cti_list = len(lutech_cti_list) - 1

for k in range(len_lutech_cti_list):       #controllo degli indirizzi della list_ip calcolata prima se sono presenti nel file della CTI Lutech
    k_list = lutech_cti_list[k+1]    
    lutech_cti_dict['ip_address'] = k_list[5]
    lutech_cti_dict['details'] = k_list[2]
    if lutech_cti_dict['ip_address'] in list_ip:
        lutech_cti_dict['timestamp'] = k_list[0]    
        lutech_cti_dict['name'] = k_list[1]
        lutech_cti_dict['geoip.country_code2'] = k_list[4]
        lutech_cti_dict['status'] = k_list[6]
        lutech_threat_feed_list.append(lutech_cti_dict.copy())

alarm = {}
list_alarm = []

for k1_list in lutech_threat_feed_list:       #creazione dell'alarm per gli ip trovati nella lista della CTI
    for k2_list in list_dns_record:
        if k1_list['ip_address'] == k2_list['ip_address']:
            alarm['dst_ip'] = k1_list['ip_address']
            alarm['src_ip'] = k2_list['client_ip']
            alarm['threat_feed'] = {'threat_feed_source': 'lutech', 'name': k1_list['name'], 'detail': k1_list['details'], 'country': k1_list['geoip.country_code2'], 'status': k1_list['status']}
            list_dns_server = [] # per una coppia src_ip e dst_ip ci possono essere delle richieste fatte a diversi server dns
            for k3_list in list_dns_record:
                if alarm['src_ip'] == k3_list['client_ip'] and alarm['dst_ip'] == k3_list['ip_address']:  # un alarm è caratterizzato univocamente dalla coppiaggg src_ip & dst_ip
                    if not k3_list['dns_server'] in list_dns_server:
                        list_dns_server.append(k3_list['dns_server'])
            alarm['dns_server'] = list_dns_server
            if not alarm in list_alarm: 
                list_alarm.append(alarm.copy())

for k in list_alarm:
    print(k)

print(datetime.now().replace(microsecond=0))