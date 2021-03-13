from socket import *
import os
import sys
import struct
import time
import select
import binascii
ICMP_ECHO_REQUEST = 8


def main():

    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = "127.0.0.1"

    ping(host)


def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = ord(string[count+1]) * 256 + ord(string[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(mySocket, ID, timeout, destAddr):

    timeLeft = timeout

    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)

        if whatReady[0] == []: # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)
        #Fill in start
        #Fetch the ICMP header from the IP packet


        # just extract the first byte from the received IP packet (the IHL can be found in the last 4 bits of the first byte)
        firstByte = recPacket[:1]

        # convert the first byte into an int
        # (it starts off as pure bytes in big endian format since IP uses big endian)
        firstByteInt = int.from_bytes(firstByte, "big")


        # right bitwise shift cuts off the last 4 bits and only leaves the first 4 bits
        # (giving the version from IP header, going to be 4 in this case)
        ipVersion = firstByteInt >> 4

        # get the last 4 bits of the first byte (E.G. in  the IP header this is the IHL)
        # The IHL is the number of 32 bit words in the IP header which represents the start of the data
        # bitwise and with 00001111 makes first 4 bits 0, and last 4 bits stay the same (leaving last 4 bits only)
        IHL = firstByteInt & 0b00001111

        # total number of bits in the IP header (number of 32 bit words * 32 = total bits)
        IHL *= 32

        # total number of bytes in the IP header
        IHL /= 8

        # convert back to an int
        # for some reason it is converting to a float even though it is dividing an int by an int, so convert back
        IHL = int(IHL)


        # extract the bytes that make up the ICMP portion of the received packet
        # (E.G. where the data starts in the IP packet)
        icmpPacket = recPacket[IHL:]


        type = icmpPacket[0:1]
        type = int.from_bytes(type, "big")

        code = icmpPacket[1:2]
        code = int.from_bytes(code, "big")

        Checksum = icmpPacket[2:4]
        Checksum = int.from_bytes(Checksum, "big")


        identifier = icmpPacket[4:6]
        identifier = int.from_bytes(identifier, "big")

        seqNum = icmpPacket[6:8]
        seqNum = int.from_bytes(seqNum, "big")



        data = icmpPacket[8:]




        print(firstByte.hex())
        print(firstByte)


        sys.exit()

        return 0


        #Fill in end
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return "Request timed out."

def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(str(header + data))
    # Get the right checksum, and put in the header

    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.



def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details:http://sock-raw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    myID = os.getpid() & 0xFFFF
     # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay


def ping(host, timeout=1):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")
    # Send ping requests to a server separated by approximately one second
    while 1 :
        delay = doOnePing(dest, timeout)
        print(delay)
        time.sleep(1)# one second
    return delay



main()