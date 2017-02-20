# Author: Mirco Gentili
# Date 20170219
# Version: 0.0.2
# Description: Cyber DNS Threat Intelligence

from datetime import datetime
from datetime import timedelta
from elasticsearch import Elasticsearch
from elasticsearch import helpers
import ipaddress
import re

index_name = "packetbeat-*"
type_name = "dns"
size_count = 50
time_delta = "00:15:00"
host = "http://192.168.47.200:9200"
es = Elasticsearch([host], timeout=100)

time_end = datetime.now().replace(microsecond=0)
(h, m, s) = time_delta.split(':')
time_start = (time_end - timedelta(hours=int(h),minutes=int(m), seconds=int(s)))
time_start = int(time_start.timestamp()) * 1000
time_end = int(time_end.timestamp()) * 1000

regex_arpa_ip = r"(\d*)\.(\d*)\.(\d*)\.(\d*)"

dns_query_a = {
    "size": size_count,
    "_source": "dns",
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
    "_source": "dns",
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

result_query_dns_a = helpers.scan(
    es, index=index_name, doc_type=type_name, query=dns_query_a)

ip_record = {}
list_ip_record = []

for k1 in result_query_dns_a:
    try:
        len_type_list = len(k1["_source"]["dns"]["answers"])
        for k2 in range(len_type_list):
            try:
                dns_type = k1["_source"]["dns"]["answers"][k2]["type"]
                if dns_type == "A":
                    try:
                        ip_address = k1["_source"]["dns"]["answers"][k2]["data"]
                        name = k1["_source"]["dns"]["answers"][k2]["name"]
                  #      dns_server = k1["_source"]["dns"]["answers"][k2]["ip"] ########trovare campo############# 
                        dns_server = "TBD"
                        ip_record = {'ip_address': ip_address, "name": name, "dns_server": dns_server}
                    except Exception as error:
                        pass
          #          if not ipaddress.IPv4Address(ip_address).is_private:
         #               list_ip_record.append(ip_record)
            except Exception as error:
                pass
    except Exception as error:
        pass

#result_query_dns_ptr = helpers.scan(
 #   es, index=index_name, doc_type='dns', query=dns_query_ptr)

#for k1 in result_query_dns_ptr:
 #   try:
  #      ip_address_arpa = k1["_source"]["dns"]["question"]["name"]
   #     list_oct_ip = list(re.findall(regex_arpa_ip, ipv4_arpa)).pop()[::-1]
    #    ip_address = str.join('.', list_oct_ip)
     #   if not ipaddress.IPv4Address(ipv4).is_private:
      #      list_ipv4.append(ipv4)
 #   except Exception as error:
  #      pass

for i in list_ip_record:
   print(i)
print(len(list_ip_record))
print(datetime.now().replace(microsecond=0))
