#!/usr/bin/env python

import scapy.all as scapy
import optparse  # argparse  only work python 3.x   but argparse is developing by developer not optparse


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()     to check output
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()       to check output
    arp_request_broadcast = broadcast/arp_request  # to combine two variable
    # arp_request_broadcast.show() to check output of combine
    # we create 2 variable because function returns  2 list elements
    answered_list, unanswered_list = scapy.srp(
        arp_request_broadcast, timeout=1, verbose=False)
    # timeout cause not stuck in code if there isn't answer
    # verbose=false  dont allows to write unnecassary words
    # print(answered_list.summary())   to check output

    clients_list = []
    for element in answered_list:
        # print(element[1].show())  output to show  what I can use  or what I can reach ip and mac address
        # elements add to dictionary first element is key second element is value
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)    # dictionary add to list
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n-------------------------------------------------")
    for client in results_list:
        print(client["ip"]+"\t\t"+client["mac"])

    # print(unanswered.summary())
    # scapy.ls(scapy.Ether())   # to show elements of ether  to use
    # print(arp_request.summary())   // output who has .......   says ......
    # scapy.ls(scapy.ARP())  to show fields of arp fuction  so I select pdst because I want a specifik IP


def get_arguments():
    parser = optparse.OptionParser()  # Create a object
    parser.add_option("-i", "--ip", dest="ip_address",
                      help="IP address to scan")
    # ==  (options,arguments) = parser.parse.args()
    options = parser.parse_args()[0]
    return options


options = get_arguments()
scan_result = scan(options.ip_address)
print_result(scan_result)
