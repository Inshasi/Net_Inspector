
#-------------------------
# Mohammed Inshasi
#-------------------------

# Put your imports within this box

from psutil import disk_usage,virtual_memory,net_if_addrs,pids,Process,win_service_get,win_service_iter

from os import getlogin,environ,getenv

from platform import system, python_version, win32_ver, release, version

from datetime import datetime

from socket import inet_aton, inet_ntoa, inet_ntop, inet_pton

#------------------------------

#-----------------------------

class Inspector:
    """This class provides tools for examining underlying platforms
    These tools could be useful for various contexts including:
    network administration, penetration testing, digital forensics
    All methods are static, so the class has no constructor
    All methods should work for both Windows and Linux
    """

    @staticmethod
    #Task 1
    def get_os_info():
        """Return a list consisting of:
        if OS is Windows:
            [OS type, release, version, edition]
        If OS is Linux:
            [OS type, release, version]
        Otherwise return []
        """
        if system() == 'Windows':
            return [system(), win32_ver()[0], win32_ver()[1], win32_ver()[3]]
        elif system() == 'Linux':
            return [system(), release(), version()]
        else:
            return []

    @staticmethod
    #Task 2
    def get_user_info():
        """returns a tuple consisting of the logined username
        along with the date/time of the login
        Make sure the date/time is formatted properly
        Should work for Windows and Linux"""
        time = datetime.now()
        time = time.strftime("%Y-%m-%d %H:%M:%S")
        return (getlogin(), time)

    @staticmethod
    #Task 3
    def get_path():
        # your code here
        c = 0
        cc = 0
        java = ''
        py = ''
        for i in getenv('PATH').split(';'):
            k = i.split('\\')
            try:
                if k[-1] == 'javapath' and c == 0:
                    java = i
                    c = 1
                if (k[-1] == 'python' or k[-2] == 'python' or k[-3] == 'python') and cc == 0:
                    py = i
                    cc = 1
            except:
                continue
        return (py, java)

    @staticmethod
    #Task 4
    def get_system_info():
        """Returns a dictionary consisting of the following items:
        'C Drive Size' : size of the C drive in GB
        'Timezone': The system time zone
        'RAM size': The size of the RAM in GB"""
        # your code here

        dsize = float("{:0.2f}".format(disk_usage('C:\\')[0] / pow(1024, 3)))

        now = datetime.now()
        local_now = now.astimezone()
        local_tz = local_now.tzinfo
        tz = local_tz.tzname(local_now)

        rsize = round(float("{:0.2f}".format(virtual_memory()[0] / pow(1024, 3))))

        return {"C Drive Size": dsize, "Timezone": tz, "RAM Size": rsize}

    @staticmethod
    #Task 5
    def get_wireless_info():
        """Returns a tuple consisting of:
        MAC address of the wireless NIC
        IPv4 address of the wireless NIC
        IPv6 address of the wireless NIC
        """
        # your code here
        W = net_if_addrs()['Wi-Fi']
        return (W[0][1], W[1][1], W[2][1])

    @staticmethod
    #Task 6
    def get_process_info(process_name):
        """Returns a list of all running processes matching the given name
        Each element in the list is [PID, process create time]"""
        # your code here
        lst = []
        for i in pids():
            try:
                if Process(i).name() == process_name:
                    tm = datetime.fromtimestamp(Process(i).create_time())
                    lst.append([i, tm])
            except:
                continue
        return lst

    @staticmethod
    #Task 7
    def get_windows_services(services):
        """check if given services are running in the system
        Returns a list where each element is:
        [service name, service display name, service status]"""
        # your code here
        lst = []
        for i in services:
            try:
                var = win_service_get(i)
                if var.status() == 'running':
                    lst.append([var.name(), var.display_name(), 'running'])
            except:
                continue
        return lst

class IPAddress:
    """This class stores IP address of both types: IPv4 and IPv6
       The class contains tools(methods) for displaying the addresses
       in different formats"""

    def __init__(self,ip):
        """Constructor
           should have one private property called __ip initialized to given ip
           You can add any private properties as you deem necessary
           If given IP is invalid, the __ip should be 127.0.0.1"""
        if self.valid_IPv4(ip) is False and self.valid_IPv6(ip) is False:
            self.__ip = '127.0.0.1'
        else:
            self.__ip = ip
        pass

    def version(self):
        """Returns the IP version of the address"""
        if self.__ip.count(':') > 0:
            return '6'
        return '4'

    def short(self):
        """Returns the short version of the address
        for IPv4 it is the same as the address
        for IPv6 it should be the shortened form"""
        # your code here
        if self.version() == '6':
            n = 0
            sh = self.__ip
            for i in range(int(len(self.__ip)/5)+1, 1, -1):
                try:
                    r = '0000:' * i
                    r = r[:-1]
                    n = self.__ip.index(r)
                    sh = sh.replace(r, ':', 1)
                    if i == int(len(self.__ip)/5)+1:
                        return '::'
                except ValueError:
                    n = -1
                    continue
            short_ipv6 = ''
            sh = sh.replace(':000', ':')
            sh = sh.replace(':00', ':')
            sh = sh.replace(':::', '::')
            s = sh.split(':')
            for i in s:
                if i == '':
                    short_ipv6 += ':'
                elif i[0] == '0' and len(i) > 1:
                    short_ipv6 += i[1:]
                else:
                    short_ipv6 += i
                short_ipv6 += ':'
            short_ipv6 = short_ipv6.replace('::::', '::')
            short_ipv6 = short_ipv6.replace(':::', '::')
            return short_ipv6[:-1]
        return self.__ip

    def __str__(self):
        """Return a string representation of the IP address in the following format:
        IPv4 = <ip_address>
        or
        IPv6 = <ip_address in short form>"""
        # your code here
        if self.version() == '4':
            return f'IPv4 = {self.short()}'
        return f'IPv6 = {self.short()}'

    def to_int_list(self):
        """format IP address as a list of integers
            For IPv4 the list consists of 4 integers
            For IPv6 the list consists of 8 integers"""
        lst = []
        if self.version() == '4':
            x = self.__ip.split('.')
            for i in range(4):
                lst.append(int(x[i]))
            return lst
        for i in self.__ip.split(':'):
            lst.append(int(i, 16))
        return lst

    def to_hex(self):
        """Generate a string representing the hexadecimal representation of the address
        For IPv4: hex values are separated by .
        For IPv6: hex values are separated by :
        """
        to_hexx = ''
        if self.version() == '4':
            for i in self.__ip.split('.'):
                to_hexx += hex(int(i))
                to_hexx += '.'
            return to_hexx[:-1]
        loop1 = self.short().split(':')
        counter = 0
        for i in loop1:
            if i == '' and counter == 0:
                to_hexx += '0x0:' * (9-len(loop1))
                counter += 1
                continue
            elif counter > 0 and i == '':
                to_hexx += '0x0:'
                continue
            to_hexx += '0x'+i+':'
        return to_hexx[:-1]

    def to_hex2(self):
        """Similar to hex1 except:
        There are no preceding 0's before \\x
        There are no separators
        """
        # your code her
        if self.version() == '6':
            return '\\x'+self.__ip.replace(':', '\\x')
        return str(inet_aton(self.__ip))[2:-1]

    def to_bytes_list(self):
        """Return a list of bytes
        Each byte corresponds to the bytes representation of the integer value"""
        lst = []
        if self.version() == '4':
            for i in list(inet_aton(self.__ip)):
                lst.append(i.to_bytes(1, 'big'))
            return lst
        x = inet_pton(socket.AF_INET6, self.__ip)
        for i in range(0, len(x), 2):
            lst.append(x[i].to_bytes(1, 'big')+x[i+1].to_bytes(1, 'big'))
        return lst

    def to_bytearray(self):
        """similar to_bytes_list, except that bytes are returned in
        a bytearray object"""
        # your code here
        if self.version() == '6':
            return bytearray(inet_pton(socket.AF_INET6, self.__ip))
        return bytearray(inet_aton(self.__ip))
    @staticmethod
    def valid_IPv4(ip_address):
        """Return True if given address is valid IPv4 address, otherwise False
        A valid IPv4 address is a string
        consisting of four integers separated by dots
        The integers have to be in the range [0,255]
        """
        if ip_address.count('.') != 3:
            return False
        try:
            inet_aton(ip_address)
            return True
        except OSError:
            return False

    @staticmethod
    def valid_IPv6(ip_address):
        """Return True if given address is valid IPv4 address, otherwise False
        A valid IPv6 should be a string in the long form
        Consisting of 8 parts separated by colon
        Each part consists of four hexadecimal numericals"""
        # your code here
        if ip_address.count(':') != 7:
            return False
        x = ip_address.split(':')
        for i in x:
            if len(i) != 4:
                return False
        try:
            inet_pton(socket.AF_INET6, ip_address)
            return True
        except OSError:
            return False

class Capture:
    """This class provides some utilities for manipulating packet capture files
    generated by WireShark"""

    def __init__(self, filename):
        """filename represent a packets capture generated by Wireshark
        Constructor sets two private properties:
        __filename: set to given filename
        __packets: set to an empty list
        """
        self.__filename = filename
        self.__packets = []
        pass

    def __str__(self):
        """Return a string representation of a Capture Object in the following format:
        (<filename>):<#packets> packets"""
        # your code here
        return f'({self.__filename}):{len(self.__packets)} packets'

    def load_packets(self):
        """Inspects the filename and load its contents into the private property packets
        If an invalid file, packets is []"""
        # your code here
        packets = []
        try:
            f = open(self.__filename, 'r').readlines()
            counter = 0
            for i in range(0, len(f)):
                if f[i][0:3] == 'No.':
                    counter = 1
                    continue
                if counter == 1:
                    strr = f[i]
                    for k in range(7):
                        if strr[0] == ' ':
                            strr = strr[1:]
                        else:
                            break
                    packets.append(strr)
                    counter = 0
            self.__packets = packets
            return packets
        except:
            return packets

    def get_packets(self,protocol=None):
        """Returns a list of packets that match the given protocol
        if protocol is None, then a list of all packets is returned"""
        lst = []
        for i in self.__packets:
            x = i.split()[4]
            if x == protocol:
                lst.append(i)
        return lst

    def __getitem__(self,indx):
        """overrides the index operator [] such that if you have
        Capture object called cap, you can use cap[i] to return the ith packet"""
        # your code here
        try:
            return self.__packets[indx]
        except:
            return None

class Packet:
    """Packet class that creates and manipulates IPv4 Packet Objects"""

    def __init__(self,packet_str):
        """The class has one private property: __packet.
        It is set to the given packet_str which is a string representation of a packet
        assume the string is formatted as packets in Capture objects
        You can add private properties as you see necessary"""
        # your code here
        if type(packet_str) != str:
            self.__packet = ''
        else:
            self.__packet = packet_str
        pass

    def info(self):
        """Returns a list consisting of two elements:
        Packet serial number
        packet capture time"""
        return [int(self.__packet.split()[0]), float(self.__packet.split()[1])]

    def IP_header(self):
        """Returns a list consisting of IPv4 header which is:
        source IP address (str)
        Destination IP address (str)
        Transport Protocol (str)
        Length (int)
        """

        return [self.__packet.split()[2], self.__packet.split()[3], self.__packet.split()[4], int(self.__packet.split()[5])]

    def TCP_Segment(self):
        """Return a list consisting of TCP Segment Header
        if the protocol in the IP header is not TCP, the output is None
        Otherwise:
            Source Port (int)
            Destination Port (int)
            Seq: Packet Sequence Number (int)
            ACK: packet acknowledgement number (int)
            flags: a list of flags (list of strings)
            window: window size (int)
            options: TCP segment options (str)
        """
        seg = []
        pkt = self.__packet.split()
        if self.IP_header()[2] == 'TCP':
            ind = pkt.index('-->')
            seg.append(int(pkt[ind-1])) # for src port
            seg.append(int(pkt[ind+1])) # for dest port

            for i in range(len(pkt)-1,0,-1):
                if pkt[i][:4] == 'Len=':
                    if str(pkt[i-3]) == '[SYN]':
                        seg.append(int(pkt[i - 2][4:]))
                        seg.append(0) # NO ACK WILL SAVE IT AS 0
                        if i-3 != ind+2:
                            seg.append([str(pkt[ind + 2])[1:-1], str(pkt[i - 3])[:-1]])
                        else:
                            seg.append([str(pkt[ind + 2][1:-1])])
                        seg.append(int(pkt[i - 1][4:]))
                    else:
                        seg.append(int(pkt[i-3][4:]))
                        seg.append(int(pkt[i-2][4:]))
                        if ind+2 != i-4:
                            seg.append([str(pkt[ind+2])[1:-1],str(pkt[i-4])[:-1]])
                        else:
                            seg.append([str(pkt[ind+2][1:-1])])
                        seg.append(int(pkt[i-1][4:]))
                    if i != len(pkt)-1:
                        strr = ''
                        for k in pkt[i+1:]:
                            if k == pkt[-1]:
                                strr += k
                                break
                            strr += k + ' '
                        seg.append(strr)
                    else:
                        seg.append('')
            return seg
        else:
            return None

    def __str__(self):
        """Return a string representaiton of a packet
        If TCP segment return both IP and TCP headers, otherwise only IP header
        see output file for formatting"""
        # your code here
        if self.TCP_Segment() is not None:
            return f'SN = {self.info()[0]}, Capture Time = {self.info()[1]}\nSource IP = {self.IP_header()[0]}, Destination IP = {self.IP_header()[1]}\nProtocol = {self.IP_header()[2]}, Length = {self.IP_header()[3]}\nSource Port = {self.TCP_Segment()[0]}, Destination Port = {self.TCP_Segment()[1]}\nSeq = {self.TCP_Segment()[2]}, Ack = {self.TCP_Segment()[3]}\nflags = {self.TCP_Segment()[4]}, window = {self.TCP_Segment()[5]}, options = {self.TCP_Segment()[6]}'
        return f'SN = {self.info()[0]}, Capture Time = {self.info()[1]}\nSource IP = {self.IP_header()[0]}, Destination IP = {self.IP_header()[1]}\nProtocol = {self.IP_header()[2]}, Length = {self.IP_header()[3]}'

class Sniffer:
    """A network packet sniffing tool"""

    def __init__(self,capture_file):
        """Receive a string representing capture filename
        Contains one private property called __packets
        Which is a list of Packet objects from the capture file"""
        # your code here

        self.__packets = Capture(capture_file).load_packets()
        pass

    def get_packets(self):
        """returns a copy of the private property __packets"""
        # your code here
        x = []
        for i in self.__packets:
            x.append(Packet(i))
        return x


    def get_syn_packets(self):
        """returns a list of Packet objects that are SYN packets
        SYN Packets are packets that contain the first packet in the
        3-way handshake"""
        # your code here

        lst = []
        pkt = self.get_packets()
        for i in range(len(pkt)):

            try:
                if pkt[i].TCP_Segment()[4][0] == 'SYN' and len(pkt[i].TCP_Segment()[4]) == 1:
                    lst.append(pkt[i])
            except TypeError:
                continue
        return lst

    def get_connection(self,syn_packet):
        """Return a list of packets that belong to a given connection
        The information should be extracted from given syn packet
        Assume that the SYN Packet is always valid"""
        # your code here
        x = syn_packet.IP_header()
        y = syn_packet.TCP_Segment()

        lst = []
        for i in self.get_packets():
            if i.IP_header()[0] == x[1] or i.IP_header()[1] == x[1]:
                if i.TCP_Segment() is not None:
                    if i.TCP_Segment()[0] == y[0] or i.TCP_Segment()[1] == y[0]:
                        lst.append(i)

        return lst


