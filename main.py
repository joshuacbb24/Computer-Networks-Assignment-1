from socket import *
import os
import sys
import struct
import time
import select
import random
ICMP_ECHO_REQUEST = 8




# can pass in the address you want as the first argument when running the script
def main():

    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = "127.0.0.1"

    host = "8.8.8.8"
    ping(host)



def switch(Type, code):

    # dicts for the different type's and their associated error codes
    switch = {
        3: {0: "\tNet Unreachable", 1: "\tHost Unreachable", 2: "\tProtocol Unreachable", 4: "\tFramgentation needed and DF set", 5: "\tSource Route Failed"},
        11: {0: "\tTTL exceeded in transit", 1: "\tFragment reassembly time exceeded"},
        12: {0: "\tPointer indicates the error"},
        4: {0: "\tGateway along the path does not have buffer space needed"},
        5: {0: "\tRedirect datagrams for the network", 1: "\tRedirect datagrams for the host", 2: "\tRedirect datagrams for the Type of service and Network", 3: "\tRedirect datagrams for the Type of Service and Host"},
    }

    codeDict = (switch.get("{}".format(Type)), "\tNo error")

    if type(codeDict) is dict:
        print(codeDict.get("{}".format(code), "\tError code not programmed"))
    else:
        print("\tNo Error")



def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = string[count+1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer







def receiveOnePing(mySocket, ID, timeout, destAddr):
    global rTrip, rMin, rMax, rSum, count, rAvg, failed

    timeLeft = timeout

    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)


        if whatReady[0] == []: # Timeout
            count += 1
            failed += 1
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


        Type = icmpPacket[0:1]
        Type = int.from_bytes(Type, "big")

        code = icmpPacket[1:2]
        code = int.from_bytes(code, "big")

        switch(Type, code)

        Checksum = icmpPacket[2:4]
        Checksum = int.from_bytes(Checksum, "big")


        identifier = icmpPacket[4:6]
        identifier = int.from_bytes(identifier, "big")

        seqNum = icmpPacket[6:8]
        seqNum = int.from_bytes(seqNum, "big")



        data = icmpPacket[8:]

        bytesInDouble = struct.calcsize("d")
        timeSent = struct.unpack("!d", recPacket[28:28 + bytesInDouble])[0]

        rTrip = timeReceived - timeSent
        rMin = min(rMin, rTrip)
        rMax = max(rMax, rTrip)
        rSum = rTrip + rSum
        count = count + 1
        rAvg = rSum / count
        return rTrip






def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("!bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, ID)

    data = struct.pack("!d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
    # Get the right checksum, and put in the header


    # if sys.platform == 'darwin':
    #     # Convert 16-bit integers from host to network byte order
    #     myChecksum = htons(myChecksum) & 0xffff
    # else:
    #     myChecksum = htons(myChecksum)

    header = struct.pack("!bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, ID)

    packet = header + data
    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.


def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")

    # SOCK_RAW is a powerful socket type. For more details:http://sock-raw.org/papers/sock_raw
    mySocket = socket(AF_INET, SOCK_RAW, icmp)

    myID = os.getpid() & 0xFFFF

    # Return the current process id
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay


def ping(host, timeout = 1):
    global rTrip, rMin, rMax, rSum, count, rAvg, failed
    rTrip = 0
    failed = 0
    rMin = float('+inf')
    rMax = float('-inf')
    rSum = 0
    count = 0
    rAvg = 0.0
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    print("")
    # Send 10 ping requests to a server separated by approximately one second
    try:
        while True:
            delay = doOnePing(dest, timeout)

            if type(delay) is int or type(delay) is float:
                print("{} ms to receive a response".format(delay * 1000))
            elif type(delay) is str:
                print(delay)

            if count != 0:
                print("Packet Loss ", 100 * failed / count, "%\n")

            time.sleep(1)  # one second

    except KeyboardInterrupt:
        print("Min RTT ", rMin * 1000, " Max RTT ", rMax * 1000, " Avg RTT ", rAvg * 1000)
        if count != 0:
            print("Packet Loss ", 100 * failed / count, "%")

    return delay



main()