import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
from scapy.all import *


from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
import binascii
import hashlib
from cryptography.fernet import Fernet


#### Message #####

message_ipv6 = "Internet Protocol version 6 (IPv6) is the most recent version of the Internet Protocol (IP), the communications protocol that provides an identification and location system for computers on networks and routes traffic across the Internet. IPv6 was developed by the Internet Engineering Task Force (IETF) to deal with the long-anticipated problem of IPv4 address exhaustion, and is intended to replace IPv4.[2] In December 1998, IPv6 became a Draft Standard for the IETF,[3] which subsequently ratified it as an Internet Standard on 14 July 2017. Devices on the Internet are assigned a unique IP address for identification and location definition. With the rapid growth of the Internet after commercialization in the 1990s, it became evident that far more addresses would be needed to connect devices than the IPv4 address space had available. By 1998, the IETF had formalized the successor protocol. IPv6 uses 128-bit addresses, theoretically allowing 2128, or approximately 3.4×1038 total addresses. The actual number is slightly smaller, as multiple ranges are reserved for special use or completely excluded from use. The two protocols are not designed to be interoperable, and thus direct communication between them is impossible, complicating the move to IPv6. However, several transition mechanisms have been devised to rectify this. IPv6 provides other technical benefits in addition to a larger addressing space. In particular, it permits hierarchical address allocation methods that facilitate route aggregation across the Internet, and thus limit the expansion of routing tables. The use of multicast addressing is expanded and simplified, and provides additional optimization for the delivery of services. Device mobility, security, and configuration aspects have been considered in the design of the protocol. IPv6 addresses are represented as eight groups of four hexadecimal digits each, separated by colons. The full representation may be shortened; for example, 2001:0db8:0000:0000:0000:8a2e:0370:7334 becomes: 2001:db8::8a2e:370:7334."


def encrypt(x,y):

    keyPair = y
    pubKey = keyPair.publickey()
    pubKeyPEM = pubKey.exportKey()

    privKeyPEM = keyPair.exportKey()
    
    length = sys.getsizeof(x)
    msg = x.to_bytes(length,'little')

    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(msg)

    decryptor = PKCS1_OAEP.new(keyPair)
    decrypted = decryptor.decrypt(encrypted)

    return encrypted



def decrypt(x,y):
    keyPair = y
    decryptor = PKCS1_OAEP.new(keyPair)
    decrypted = decryptor.decrypt(x)
    return decrypted




def endecryptaes(key,data, option):
    length = sys.getsizeof(data)
    #print('LENGTH:', length)
    #msg = data.to_bytes(length,'big')
    msg = bytes(data, 'utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    
    aesCipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, tag)

    if option==1:
        return  nonce + ciphertext + tag
    elif option==2:
        return plaintext


##### Key Generation #####
keyPair = RSA.generate(3072)
password='arnau'
key = hashlib.sha256(password.encode()).digest()


ans=True
while ans:
    print ("""
    1.Show Original message
    2.Encrypt message using AES
    3.Send Message
    4.Exit/Quit
    """)
    ans = input("What would you like to do? \n") 
    if ans=="1":  
      print("\nORIGINAL MESSAGE: \n",message_ipv6)   
    elif ans=="2":
      encrypt_message = endecryptaes(key,message_ipv6,1)
      print("\nENCRYOTED MESSAGE: \n",encrypt_message) 
    elif ans=="3":
        decriptedaes = endecryptaes(key,message_ipv6,2)
        print("\nSending....... \n\n",decriptedaes)
                ##### Flow label #####
        x1 = ord('a')
        ##### Payload length #####
        x2 = ord('r')
        ##### Payload length #####
        x3 = ord('n')
        ##### Payload length #####
        x4 = ord('a')
        ##### Hop limit #####
        x5 = ord('u')

        ####Packet construction####
        h=IPv6()
        h.src="2100::102"
        h.tc=x1
        h.fl=x2
        h.plen=x3
        h.hlim=x4
        h.nh=x5

        extension = IPv6ExtHdrHopByHop()

        packet = h/extension
        #h=IPv6(dst="::1", tc=y1, fl=y2, plen=y3, hlim=y4, nh=y5)
        send(packet)
        #send(Ether()/h/ICMPv6EchoRequest(data=encrypt_message))
        #h.show()
        packet.show()


        print('Complete\n')
    elif ans=="4":
      print("\n Goodbye") 
      break
    elif ans !="":
      print("\n Not Valid Choice Try again") 



'''

RSA encryption:


##### Traffic class #####
tc=4
encrypted = encrypt(tc,keyPair)
encrypted_tc = encrypted
str_tc = str(4)
#ciphertext_tc = int.from_bytes(encryptaes(key,tc),byteorder='big',signed=False)
#ciphertext_tc = encryptaes(key,tc)
decrypted_tc = decrypt(encrypted,keyPair)

##### Hop limit #####

hl=85
encrypted = encrypt(hl,keyPair)
encrypted_hlim = int.from_bytes(encrypted,"big")
decrypted_hlim = decrypt(encrypted,keyPair)

#ciphertext_hl = int.from_bytes(encryptaes(key,hl)[:1],byteorder='big',signed=False)

string = "arnau"

encoded = string.encode('utf-8')
##### Flow label #####
y1 = int.from_bytes(encoded[:1],byteorder='big',signed=False)
##### Payload length #####
y2 = int.from_bytes(encoded[1:2],byteorder='big',signed=False)
##### Payload length #####
y3 = int.from_bytes(encoded[2:3],byteorder='big',signed=False)
##### Payload length #####
y4 = int.from_bytes(encoded[3:4],byteorder='big',signed=False)
##### Hop limit #####
y5 = int.from_bytes(encoded[4:5],byteorder='big', signed=False)
'''
