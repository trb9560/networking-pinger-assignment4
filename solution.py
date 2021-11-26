from socket import *
import os
import sys
import struct
import time
import select
import binascii
import statistics
from array import array
# Should use stdev

ICMP_ECHO_REQUEST = 8


def header2dict(names, struct_format, data):
    """ unpack the raw received IP and ICMP header information to a dict """
    unpacked_data = struct.unpack(struct_format, data)
    return dict(zip(names, unpacked_data))


def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


'''
called from doOnePing
In this manner:
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr) #  RECEIVE
return delay
'''
def receiveOnePing(mySocket, ID, timeout, destAddr):
    global rttMin, rttMax, rttCounter, rttSum, packetLen, timeToLive

    timeLeft = timeout

    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            print("Request timed out.[1]")
            return "Request timed out.[1]"

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fill in start

        # Fetch the ICMP header from the IP packet

        icmpHeader = recPacket[20:28]

        rawTTL = struct.unpack("s", bytes([recPacket[8]]))[0]
        TTL = int(binascii.hexlify(rawTTL), 16)

        icmpType, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
        if icmpType != 0:
            print('expected type=0, but got {}'.format(icmpType))
            return 'expected type=0, but got {}'.format(icmpType)
        if code != 0:
            print('expected code=0, but got {}'.format(code))
            return 'expected code=0, but got {}'.format(code)
        if packetID != ID:
            print('expected id={}, but got {}'.format(ID, packetID))
            return 'expected id={}, but got {}'.format(ID, packetID)
        send_time = struct.unpack('d', recPacket[28:])

        '''
        if code != 0:
             return 'expected code=0, but got {}'.format(code)
        if type != 0:
            return f'expected type 0 but got {code}'
        if recID != ID:
            return f'expected id={ID} but got {recID}'
            
        payload = struct.unpack('b', recPacket[28:])
        rtt = timeReceived - payload
        return rtt

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."
        
        '''

        if packetID == ID:  # Our packet
            byte_in_double = struct.calcsize("!d")
            timeSent = struct.unpack("d", recPacket[28:28 + byte_in_double])[0]

            rtt = (timeReceived - timeSent) * 1000
            packetLen = len(recPacket)  # set globals
            timeToLive = TTL  # set globals

            print("Reply from %s: bytes=%d time=%f5ms TTL=%d" % \
                   (destAddr, len(recPacket), (timeReceived - timeSent) * 1000, TTL))

            return (timeReceived - timeSent) * 1000
#            return "Reply from %s: bytes=%d time=%f5ms TTL=%d" % \
#                  (destAddr, len(recPacket), (timeReceived - timeSent) * 1000, TTL)

        # Fill in end
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            print("Request timed out.[3]")
            return "Request timed out.[3]"


'''
Much like receiveOnePing, shown above, this method is also
called from doOnePing
In this manner:
    sendOnePing(mySocket, destAddr, myID) #  SEND
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    
Called FIRST
'''
def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)

    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data

    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str

    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.


'''
Called by: ping , inside the for loop
the return value will be printed to stdout , as a variable named 'delay'
'''
def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")

    # SOCK_RAW is a powerful socket type. For more details:  http://sockraw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)

    pid = os.getpid()
    # myID = os.getpid() & 0xFFFF  # Return the current process i
    myID = pid
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay


def ping(host, timeout=1):
    global rttMin, rttMax, rttCounter, rttSum, packetLen, timeToLive

    delays = array('d', [0.0, 0.0, 0.0, 0.0])
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")

    # Send ping requests to a server separated by approximately one second
    for i in range(0, 4):
        delay = doOnePing(dest, timeout)
        delays[i] = delay
        #print(delay)
        time.sleep(1)  # one second

    # Calculate vars values and return them
    packet_min = min(delays)
    packet_avg = (sum(delays) / len(delays))
    packet_max = max(delays)
    stdev_var = statistics.stdev(delays)
    vars = [str(round(packet_min, 2)), str(round(packet_avg, 2)), str(round(packet_max, 2)), str(round(stdev_var, 2))]

    return vars


if __name__ == '__main__':
    ping('www.google.com')
