#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import select

FIRST_DELAY = 0
SECOND_DELAY = 0
THIRD_DELAY = 0

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')        #ping
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],                   #traceroute
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')   #web
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')      #proxy
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout):
        timeRemaining = timeout
        while True:
                startSelect = time.time()
                ready = select.select([icmpSocket],[],[],timeRemaining)
                selectTime = (time.time() - startSelect)
                if ready[0] == []: return "0: Destination Unreachable"              
                receive = time.time()
                receivedPac, addr = icmpSocket.recvfrom(1024)
                header = receivedPac[20:28] 
                type, code, checksum, packetid, seq = struct.unpack("bbHHh", header)
                if packetid != ID:
                    bytesInDouble = struct.calcsize("d")
                    timeSent = struct.unpack("d" ,receivedPac[28:28 + bytesInDouble])[0]
                    return receive - timeSent
                timeRemaining = timeRemaining - selectTime
                if timeRemaining <= 0: return               
        # 1. Wait for the socket to receive a reply
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        # 4. Unpack the packet header for useful information, including the ID
        # 5. Check that the ID matches between the request and reply
        # 6. Return total network delay
        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):

        myChecksum = 0
        seqNumber = 0
        ICMP_ECHO = 8      

        # 1. Build ICMP header
        header = struct.pack("!bbHHh", ICMP_ECHO, 0, myChecksum, ID, 1)
        bytesInDouble = struct.calcsize("b")
        data = (192 - bytesInDouble) * "Q"
        data = struct.pack(bytes("d", encoding='utf8'), time.time()) + bytes(data, encoding='utf8')

        # 2. Checksum ICMP packet using given function
        myChecksum = self.checksum(header + data)

        # 3. Insert checksum into packet
        header = struct.pack("!bbHHh", ICMP_ECHO, 0, socket.htons(myChecksum), ID, 1)
        packet = header + data
        global sizeOfPacket
        sizeOfPacket = sys.getsizeof(packet)

        # 4. Send packet using socket
        # 5. Record time of sending
        sendtime = icmpSocket.sendto(packet, (destinationAddress, 1))
        pass

    def doOnePing(self, destinationAddress, timeout):

        # 1. Create ICMP socket
        icmp = socket.getprotobyname("icmp")
        id = os.getpid() & 0xFFFF
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.errno (errno, msg):
            if errno == 1:                          #no permission
                raise socket.error(msg)
            raise

        # 2. Call sendOnePing function
        self.sendOnePing(my_socket, destinationAddress, id)

        # 3. Call receiveOnePing function
        delay = self.receiveOnePing(my_socket, destinationAddress, id, 5)

        # 4. Close ICMP socket
        my_socket.close()

        # 5. Return total network delay
        return delay
        pass

    def __init__(self, args):

        # 1. Look up hostname, resolving it to an IP address
        print('Ping to: %s...' % (args.hostname))
        hostAddress = socket.gethostbyname(args.hostname)

        # 2. Call doOnePing function, approximately every second
        while True:
            time.sleep(1-time.monotonic() % 1)
            ping = self.doOnePing(hostAddress, 5)
            # 3. Print out the returned delay (and other relevant details) using the printOneResult method
            self.printOneResult(hostAddress, sizeOfPacket, ping * 1000, 55, args.hostname)
        
        # 4. Continue this process until stopped


class Traceroute(NetworkApplication):

    def get_host_by_ip(self, hostaddr):
        try:
            host = socket.gethostbyaddr(hostaddr)
            nameip = nameip = '{0} ({1})'.format(hostaddr, host[0])
        except Exception:
            nameip = hostaddr
        return nameip

    def hop_route(self, destinationAddress, timeout, maxhops, tries):
        destAddr = destinationAddress
        timeLeft = timeout
        for ttl in range(1, maxhops):

            for trying in range (tries):
                #Make new socket    
                icmp = socket.getprotobyname("icmp")
                mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

                #Concat at the end
                mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
                mySocket.settimeout(timeout)
                try:
                    d = self.doOnePacket()
                    mySocket.sendto(d, (destAddr, 0))
                    t = time.time()
                    startSelect = time.time()
                    ready = select.select([mySocket],[],[], timeout)
                    timeInSelect = (time.time() - startSelect)
                    if ready == []: 
                        print("Request timed out...")
                    recvPacket, addr = mySocket.recvfrom(1024)
                    timeRecieved = time.time()
                    timeLeft = timeLeft - timeInSelect
                    if timeLeft <=0:
                        print("Request timed out...")
                except socket.timeout:
                    continue
                else:
                    icmpHeader = recvPacket[20:28]
                    requestType, code, checksum, packetID, seq = struct.unpack("bbHHh", icmpHeader)

                    if requestType == 11:
                        bytes = struct.calcsize("d")
                        sentTime = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        if trying == 0: FIRST_DELAY = (timeRecieved - t)*1000
                        if trying == 1: SECOND_DELAY = (timeRecieved - t)*1000
                        if trying == 2: THIRD_DELAY = (timeRecieved - t)*1000
                        #print(" %d  rtt=%0.f ms %s" %(ttl,(timeRecieved - t)*1000, addr[0]))
                    elif requestType == 3:
                        bytes = struct.calcsize("d")
                        sentTime = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        if trying == 0: FIRST_DELAY = (timeRecieved - t)*1000
                        if trying == 1: SECOND_DELAY = (timeRecieved - t)*1000
                        if trying == 2: THIRD_DELAY = (timeRecieved - t)*1000
                        #print(" %d  rtt=%0.f ms %s" %(ttl,(timeRecieved - t)*1000, addr[0]))
                    elif requestType == 0:
                        bytes = struct.calcsize("d")
                        sentTime = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                        if trying == 0: FIRST_DELAY = (timeRecieved - sentTime)*1000
                        if trying == 1: SECOND_DELAY = (timeRecieved - sentTime)*1000
                        if trying == 2: THIRD_DELAY = (timeRecieved - sentTime)*1000
                        #print(" %d  rtt=%0.f ms %s" %(ttl,(timeRecieved - sentTime)*1000, addr[0]))
                        return
                    else:
                        print ("error...")
                        break
                finally:
                    mySocket.close()
            print(" %d  %s %0.f ms  %0.f ms  %0.f ms" %(ttl, self.get_host_by_ip(addr[0]), FIRST_DELAY, SECOND_DELAY, THIRD_DELAY))
        pass

    def doOnePacket(self):
        tChecksum = 0
        tID = os.getpid() & 0XFFFF
        ICMP_ECHO_REQUEST = 8

        # 1. Similarly to the sendOnePing method, we firstly build our ICMP header with 0 checksum
        tHeader = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, tChecksum, tID, 1)

        tData = struct.pack("d", time.time())

        # 2. Append the checksum on the header
        tChecksum = socket.htons(self.checksum(tHeader + tData))
        tHeader = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, tChecksum, tID, 1)
        
        #create a packet and return it
        tPacket = tHeader + tData
        return tPacket
        pass

    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Traceroute to: %s...' % (args.hostname))
        adrr = socket.gethostbyname(args.hostname)
        print('Address at: %s' % socket.gethostbyname(args.hostname))
        s = self.doOnePacket()
        f = self.hop_route(adrr, 5, 30, 3)



class WebServer(NetworkApplication):

    def handleRequest(self, tcpSocket):
        # 1. Receive request message from the client on connection socket
        while True:
            connection,addr = tcpSocket.accept()
            req = connection.recv(1024).decode('utf-8')
            stringList = req.split(' ')

            func = stringList[0]
            requestedFile = stringList[1]

            print('Requesting:', requestedFile)

            my_file = requestedFile.split('?')[0]
            my_file = my_file.lstrip('/')
            if my_file == '':
                my_file = 'index.html' 

            try:
                file = open(my_file, 'rb')
                output = file.read()

                file.close()

                header = 'HTTP/1.1 200 OK\n'

                header += 'Content-Type: ' + 'text/html' + '\n\n'          ########################################
            
            except Exception as e: 
                print("Error")
                header = 'HTTP/1.1 404 Not Found\n\n'
                output = '<html><body><center><h1> Not Found (404) </h1><p> Sample HTTP Server</p></center></body></html>'.encode('utf-8')

            finalOutput = header.encode('utf-8')
            finalOutput += output
            connection.send(finalOutput)
            connection.close()
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        # 3. Read the corresponding file from disk
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        pass

    def __init__(self, args):
        HOST = '127.0.0.1'
        PORT = 8080
        print('Web Server starting on port: %i...' % (PORT))
        print('Address at %s' % (socket.gethostbyname(HOST)))

        # 1. Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # 2. Bind the server socket to server address and server port
        server_socket.bind((HOST, PORT))

        # 3. Continuously listen for connections to server socket
        server_socket.listen(1)
        self.handleRequest(server_socket)
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        # 5. Close server socket


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
