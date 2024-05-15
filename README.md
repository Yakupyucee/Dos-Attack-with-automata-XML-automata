This project will attack according to data received from a function that finds all IPs in a network (e.g., 176.182.2.1-10) within a certain range. When the IPs in this range run out (176.182.2.11-20), it will attack those between 11 and 20, reaching a certain limit. to go until. This attacked IP will be attacked based on data coming from a function within a certain range of open port numbers (e.g. 1-256). When these ports are finished, the ports between 257-512 will be found and these ports will be searched intermittently until a certain limit is reached. This DFA and the program allows attacking the desired IP address range according to the incoming data.
![image](https://github.com/Yakupyucee/Dos-Attack-with-automata-XML-automata/assets/101170223/b186b12a-106a-4fed-9da8-fc1d0922cafd)

#Alphabet

Y => If a new IP has arrived OR if there is an IP list to be sorted OR if there is an IP in the list OR
If there is a Port list to be sorted OR if the Port is present in the list OR the port to be attacked
if left.

N =>If there is no IP list to be sorted OR if there is no IP in the list OR a Port to be sorted
If there is no list OR if the Port is not available in the list.

#Situations
s0 (obtaining IP): This is the starting point of the program. In this case, the program requests an IP from the user.
It does.

s1 (IP search): This status finds the entered IP and available IPs within a certain range.

s2 (IP listing): This creates a list of found IPs and sends them one by one.
provides.

s3 (Searching ports): This finds the available ports in the sent IP.

s4 (Listing Ports): This creates a list of found Ports and selects Ports one by one.
allows it to be sent.

s5 (Attack occurs): This attacks the sent IP and port.
