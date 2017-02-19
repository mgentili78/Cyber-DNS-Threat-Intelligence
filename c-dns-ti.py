#Author: Mirco Gentili
#Date 20170219
#Version: 0.0.1
#Description: Cyber DNS Threat Intelligence

from datetime import datetime
from datetime import timedelta
from elasticsearch import Elasticsearch
import re
import ipaddress

index_name = "packetbeat-*"
type_name = "dns"
size_count = 10000
time_end = datetime.now().replace(microsecond=0)
time_delta = "00:15:00"
(h, m, s) = time_delta.split(':')

time_start = (time_end - timedelta(hours=int(h), minutes=int(m), seconds=int(s)))
time_start = int(time_start.timestamp())*1000
time_end = int(time_end.timestamp())*1000

regex_arpa_ip = r"(\d*)\.(\d*)\.(\d*)\.(\d*)"

list_ipv4 = []

es = Elasticsearch(['http://192.168.47.200:9200'])
result_query_a = es.search(index_name, type_name, {
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
                    "match": {
                        "status": {
                            "query": "OK",
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

})

len_list_hits = len(result_query_a["hits"]["hits"])

try:
    for k1 in range(len_list_hits):
        len_type_list = len(result_query_a["hits"]["hits"][k1]["_source"]["dns"]["answers"])
        for k2 in range(len_type_list):
            dns_type = result_query_a["hits"]["hits"][k1]["_source"]["dns"]["answers"][k2]["type"]
            if dns_type == "A":
                ipv4 = result_query_a["hits"]["hits"][k1]["_source"]["dns"]["answers"][k2]["data"]
                if not ipaddress.IPv4Address(ipv4).is_private:
                    list_ipv4.append(ipv4)
except Exception as error:
    print("Error")

es = Elasticsearch(['http://192.168.47.200:9200'])
result_query_ptr = es.search(index_name, type_name, {
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
    },

})

len_list_hits = len(result_query_ptr["hits"]["hits"])

try:
    for k1 in range(len_list_hits):
        ipv4_arpa = result_query_ptr["hits"]["hits"][k1]["_source"]["dns"]["question"]["name"]
        list_oct_ipv4 = list(re.findall(regex_arpa_ip, ipv4_arpa)).pop()[::-1]
        ipv4 = str.join('.', list_oct_ipv4)
        if not ipaddress.IPv4Address(ipv4).is_private:
            list_ipv4.append(ipv4)
except Exception as error:
    print("Error")

for i in list_ipv4:
    print(i)
print(len(list_ipv4))

