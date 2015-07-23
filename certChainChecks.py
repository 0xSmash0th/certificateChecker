#!/usr/bin/python3

import argparse, OpenSSL, sys, os, re, dns.resolver, time, datetime, urllib.request

class x509checks:
    """A module with custom x509 certificate checks.
    Requires one PEM encoded cert with begin and end line intact by string,
    a ip:port."""
    ###############################################
    ##The object data structure is a list with the following
    ##information at the given index.
    ##all changes and updates to the data structure should be made here
    ##an effort was made to include any information that may change as security standards change here
    ##############################################
    PEM = 0 #PEM string from user input
    IP = 1 #IP address pulled from filename
    PORT = 2 #yep you guessed it
    XOB = 3 #x509 pyopenssl object, use methods on this index
    CN = 4 #commonName succsesfully resolved
    FCN = 5 #commonName that failed resolution
    XXOB = 6 #x509 pyopenssl extension object, contains subject alt names
    SAN = 7 #List of subject alt names
    FSAN = 8 #List of tuples, failed san and what it resolves to
    ISRT = 9 #Root cert, True if cert is found in local root cert store
    RVOK = 10 #Tuple of IP:Port, Ser #, revoked status, revoked reason, revoked date.
    secureSigAlgoList = ["sha224WithRSAEncryption", "sha256WithRSAEncryption","sha384WithRSAEncryption","sha512WithRSAEncryption"]
    caCertPath = '/etc/ssl/certs'
    shortestSecureKeyLength = 2048

    def __init__(self, cert, ipPort):
        """Create object with pem string,
        preload answers for security checks not directly
        accessible from the pyopenssl object"""
        #Create list with x509 objects
        self._cert = cert
        self._ipPort = ipPort
        self._x509list = self.__createX509list(self._cert)
        #add IP
        self.__addExplicitIPnPort()
        #add x509 object
        self.__loadx509objectsFromString()
        #add resolved commonNames
        #and unresolved commonNames
        self.__getCommonName()
        #add x509 extensions that may contain subject alternative names
        self.__getx509extensions()
        #parse x509 extensions for subject alternative names
        self.__getSubjectAlternativeNames()
        #Get Root Certificate Subject Key Identifiers from local cert store
        self._caCertSubjectKeyIDs = self.__getCAcertSubjectKeyIDs()
        #check if root certificate and set flag
        self.__getIsRootCert()
        #check if the cert is revoked, add timestamp so the progress bar only spams once every 10 seconds
        self._startTime = time.time()
        self.__getRevokedStatus()

    def __createX509list(self, certFileName):
        """Create list to use as data struct for object, explicit None is usefull for
        error checks. Depending on how addition features are added you may not need to
        add None to an additional index here. However, existing error checking in functions
        require None at index"""
        x509list = [certFileName, None,None,None,None,None,None,None,None,None,None]
        return x509list

    def __addExplicitIPnPort(self):
        """Load IP and port into seperate idx of list"""
        ipPortSplit = self._ipPort.split(':', maxsplit=1)
        #minor error checking with list len check and isdigit on port#
        if len(ipPortSplit) > 2 or not ipPortSplit[1].isdigit():
            print("Explicit IP:Port parameter parse failure.")
        else:
            self._x509list[self.IP]= ipPortSplit[0]
            self._x509list[self.PORT] = ipPortSplit[1]

    def __loadx509objectsFromString(self):
        """Load pyopenssl x509object to list from PEM string."""
        try:
            self._x509list[self.XOB] = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,self._x509list[self.PEM])
        except OpenSSL.crypto.Error as e:
            print(e, "For file: ", self._x509list[self.PEM])

    def __getDNSrecords(self, name, correctIndex, failedIndex):
        """Resolve hostnames from CN or SAN function, add results in the form of a
        list of tuples to correct or failed index supplied by calling function"""
        try:
            answers = dns.resolver.query(name)
            for answer in answers:
                if str(answer) == self._x509list[self.IP]:
                    self._x509list[correctIndex].append((answer, name))
                else:
                    self._x509list[failedIndex].append((answer, name))
        except dns.resolver.NoAnswer:
            self._x509list[failedIndex].append(("No Answer from DNS query for: ", str(name)))
        except dns.resolver.NXDOMAIN:
            self._x509list[failedIndex].append(("No such domain", str(name)))
        except dns.resolver.NoNameservers:
            self._x509list[failedIndex].append(("No Nameservers for: ", str(name)))


    def __getCommonName(self):
        """Adds a list of tuples (hostname,dns rec) for commonNames at CN index and a list of tuples with
        commonNames that resolved to a diffrent IP(or nothing)than the system the
        commonName was found on at FCN index."""
        self._x509list[self.CN] = []
        self._x509list[self.FCN] = []
        if self._x509list[self.XOB] != None: #check if x509 object exists
            commonName = self._x509list[self.XOB].get_subject().commonName
            if commonName != None:#check if commonName exists
                self.__getDNSrecords(commonName, self.CN, self.FCN)
            else:#create list of tuple for error so all output is standard
                self._x509list[self.FCN].append(("commonName does not exist for x509Object :" , str(commonName)))
        else:#create list of tuple for error so all output is standard
            self._x509list[self.FCN].append(("x509 object does not exist for: ", str(key)))

    def __getx509extensions(self):
        """Adds the pyopenssl extension object to the list at XXOB"""
        if self._x509list[self.XOB] != None: #check if x509 object exists
            self._x509list[self.XXOB] = []
            for extension in range(0,self._x509list[self.XOB].get_extension_count()):
                try:
                    self._x509list[self.XXOB].append(self._x509list[self.XOB].get_extension(extension))
                except OpenSSL.crypto.Error:
                    print("x509 extension object failed to load for: " + str(self._x509list[self.IP]) + ":"+ str(self._x509list[self.PORT])+" Manual inspection necessary")

    def __getSubjectAlternativeNames(self):
        self._x509list[self.SAN] = []
        self._x509list[self.FSAN] = []
        if self._x509list[self.XXOB] != None: #check if x509 extension object exists
            for extension in self._x509list[self.XXOB]:
                #look at each x509 extension for subjectAltName 
                if bytes.decode(extension.get_short_name()) == 'subjectAltName':
                    for subAltName in str(extension).split(","):
                        subAltName = subAltName[subAltName.find("DNS:")+4:]
                        self.__getDNSrecords(subAltName, self.SAN, self.FSAN)
        else:#create list of tuple for error so all output is standard
            self._x509list[self.FSAN].append(("x509 extension object does not exist for: ", str(self._x509list[self.PEM])))

    
    def __getCAcertSubjectKeyIDs(self):
        """Creates and returns a list of x509 certificate Subject Key Identifiers <fingerprint> from the local certificate store"""
        caCertSubjectKeys = []
        for filename in os.listdir(self.caCertPath):
            with open(self.caCertPath +"/"+ filename, 'r') as caCertFile:
                try:
                    caExtensions = self.__getCAx509extensions(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,caCertFile.read()))
                    print('None found in caExtensions') if None in caExtensions else None
                    caCertSubjectKeys.append(self.__getCertExtensionsDataByShortName('subjectKeyIdentifier', caExtensions))
                except OpenSSL.crypto.Error as e:
                    print(e, "Loading CA certs from local store")
        return caCertSubjectKeys
    
    def __getCAx509extensions(self, caX509Obj):
        """Adds the pyopenssl extension objects from a CA cert to a list.
        Will skip adding a None Type exensions object, this occurs because
        the cert may be to old to have a v3 extension"""
        caExtensions = []
        for extension in range(0,caX509Obj.get_extension_count()):
            try:
                caExtensions.append(caX509Obj.get_extension(extension))
            except OpenSSL.crypto.Error:
                print("x509 Certificate Authority extension object failed to load for: " + str(self._x509list[self.IP]) + ":"+ str(self._x509list[self.PORT])+" Manual inspection to determine if root certificate is necessary")
        return caExtensions

    def __getCertExtensionsDataByShortName(self, shortName, caExtensions):
        for extension in caExtensions:
            if bytes.decode(extension.get_short_name()) == shortName:
                return str(extension)

    def __getIsRootCert(self):
        certSubjectKeyID = self.__getCertExtensionsDataByShortName('subjectKeyIdentifier', self._x509list[self.XXOB])
        if certSubjectKeyID in self._caCertSubjectKeyIDs and certSubjectKeyID != None:
            self._x509list[self.ISRT] = True

    def __getURL(self, url):
        try:
            local_filename, headers = urllib.request.urlretrieve(url, None, self.__reportHook)
        except urllib.error.URLError as error:
            print(error,"for: ", self._x509list[self.IP],":", self._x509list[self.PORT])
            return False
        return local_filename

    def __reportHook(self, blocknum, blocksize, totalsize):
        readSoFar = blocknum * blocksize
        printTime = self._startTime + 5 
        if totalsize > 0 and readSoFar <= totalsize and time.time() >= printTime:
            self._startTime = time.time()
            print("Downloaded "+ '{:.2%}'.format(readSoFar/totalsize) + " of " + str(totalsize) +" for "+ self._ipPort )

    def __getRevokedStatus(self):
        """Adds tuple of revoked status, Ser #, revoked reason, revoked date
        and url for CRL to RVOK index"""
        self._x509list[self.RVOK] = (False,
                hex(self._x509list[self.XOB].get_serial_number()),None, None, None)#Default tuple until crlURL found
        crlURL = self.__getCertExtensionsDataByShortName('crlDistributionPoints', self._x509list[self.XXOB])
        if crlURL != None:
            crlURL = crlURL[crlURL.rfind('URI:') + 4:].strip()
            self._x509list[self.RVOK] = (False,
                hex(self._x509list[self.XOB].get_serial_number()),None, None, crlURL)#Default tuple until crl match found
            print(crlURL)
            getURLresponse = self.__getURL(crlURL)
            if getURLresponse != False:#check if get URL was succsessfull. if so, then continue...
                with open(getURLresponse,'rb') as crlFile:
                    crlObj = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, crlFile.read())
                if not crlObj.get_revoked() == None:
                    for revoked in crlObj.get_revoked():
                        if int(bytes.decode(revoked.get_serial()),16) == self._x509list[self.XOB].get_serial_number():
                            self._x509list[self.RVOK] = (True,
                                 hex(self._x509list[self.XOB].get_serial_number()),
                                 bytes.decode(revoked.get_reason()),
                                 datetime.datetime.strptime(bytes.decode(revoked.get_rev_date())[:-1],"%Y%m%d%H%M%S"),
                                 crlURL)

    def __printCNnSANcheckFormater(self, ip, port, hostname, dnsResolve, result):
        print('{:<20}'.format(ip + ":" + port) + '{:<30}'.format(hostname) + '{:<20}'.format(str(dnsResolve)) + result)

    def __printPubKeyCheckFormater(self, ip, port, keyLength, result):
        print('{:<20}'.format(ip + ":" + port) + '{:^20}'.format(keyLength) + '{:<20}'.format(result))

    def __printNotAfterCheckFormater(self, ip, port, notAfterDate, result):
        print('{:<20}'.format(ip + ":" + port) + '{:<25}'.format(notAfterDate)+ '{:<20}'.format(result))

    def __printSigAlgoCheckFormater(self, ip, port, sigAlgo, result):
        print('{:<20}'.format(ip + ":" + port) + '{:<30}'.format(sigAlgo) + '{:<20}'.format(result))

    def __printRevokedCheckFormater(self, result):
        print('{:<20}'.format(self._x509list[self.IP] + ":" + self._x509list[self.PORT]) + '{:<20}'.format(str(self._x509list[self.RVOK][1])) + '{:<25}'.format(str(self._x509list[self.RVOK][2])) +'{:<25}'.format(str(self._x509list[self.RVOK][3])) +'{:<40}'.format(result) +'{:<20}'.format(str(self._x509list[self.RVOK][4])))

    def getIP(self):
        return self._x509list[self.IP]

    def getPort(self):
        return self._x509list[self.PORT]

    def printCNnSANcheck(self):
        ip = self._x509list[self.IP] #var rename for code readability
        port = self._x509list[self.PORT]
        if not self._x509list[self.ISRT]:
            [self.__printCNnSANcheckFormater(ip,port, goodCN[1], goodCN[0], "Correct CN") for goodCN in self._x509list[self.CN]]
            [self.__printCNnSANcheckFormater(ip,port,badCN[1],badCN[0],"\033[31mFailed CN\033[0m") for badCN in self._x509list[self.FCN]]
            [self.__printCNnSANcheckFormater(ip,port,goodSAN[1],goodSAN[0],"Correct SAN") for goodSAN in self._x509list[self.SAN]]
            [self.__printCNnSANcheckFormater(ip,port,badSAN[1],badSAN[0],"\033[31mFailed SAN\033[0m") for badSAN in self._x509list[self.FSAN]]
        else:
            [self.__printCNnSANcheckFormater(ip,port, goodCN[1], goodCN[0], "Correct CN ##Root Cert##") for goodCN in self._x509list[self.CN]]
            [self.__printCNnSANcheckFormater(ip,port,badCN[1],badCN[0],"\033[31mFailed CN ##Root Cert##\033[0m") for badCN in self._x509list[self.FCN]]
            [self.__printCNnSANcheckFormater(ip,port,goodSAN[1],goodSAN[0],"Correct SAN ##Root Cert##") for goodSAN in self._x509list[self.SAN]]
            [self.__printCNnSANcheckFormater(ip,port,badSAN[1],badSAN[0],"\033[31mFailed SAN ##Root Cert##\033[0m") for badSAN in self._x509list[self.FSAN]]

    def printPubKeyCheck(self):
        keylength = self._x509list[self.XOB].get_pubkey().bits()
        if not self._x509list[self.ISRT]:
            if keylength >= self.shortestSecureKeyLength:
                self.__printPubKeyCheckFormater(self._x509list[self.IP],
                self._x509list[self.PORT],
                str(keylength), "Correct Public Key length")
            else:
                self.__printPubKeyCheckFormater(self._x509list[self.IP],
                self._x509list[self.PORT],
                str(keylength) , "\033[31mFailed Public Key length\033[0m")
        else:
            if keylength >= self.shortestSecureKeyLength:
                self.__printPubKeyCheckFormater(self._x509list[self.IP],
                self._x509list[self.PORT],
                str(keylength), "Correct Public Key length ##Root Cert##")
            else:
                self.__printPubKeyCheckFormater(self._x509list[self.IP],
                self._x509list[self.PORT] ,
                str(keylength) , "\033[31mFailed Public Key length ##Root Cert##\033[0m")


    def printNotAfterCheck(self):
        notAfterDate = bytes.decode(self._x509list[self.XOB].get_notAfter())
        notAfterDate = datetime.datetime.strptime(notAfterDate[:-1],"%Y%m%d%H%M%S")
        currentTime = datetime.datetime.now()
        if not self._x509list[self.ISRT]:
            if currentTime + datetime.timedelta(days=60) >= notAfterDate:
                self.__printNotAfterCheckFormater(self._x509list[self.IP],
                        self._x509list[self.PORT],
                        str(notAfterDate),"\033[31mFailed: Certificate to expire in 60 days\033[0m")
            elif currentTime >= notAfterDate:
                self.__printNotAfterCheckFormater(self._x509list[self.IP],
                        self._x509list[self.PORT],
                        str(notAfterDate),"\033[31mFailed: Expired Certificate\033[0m")
            else:
                self.__printNotAfterCheckFormater(self._x509list[self.IP],
                        self._x509list[self.PORT],
                        str(notAfterDate),"Correct: Certificate not expired")
        else:
            if currentTime + datetime.timedelta(days=60) >= notAfterDate:
                self.__printNotAfterCheckFormater(self._x509list[self.IP],
                        self._x509list[self.PORT],
                        str(notAfterDate),"\033[31mFailed: Certificate to expire in 60 days ##Root Cert##\033[0m")
            elif currentTime >= notAfterDate:
                self.__printNotAfterCheckFormater(self._x509list[self.IP],
                        self._x509list[self.PORT],
                        str(notAfterDate),"\033[31mFailed: Expired Certificate ##Root Cert##\033[0m")
            else:
                self.__printNotAfterCheckFormater(self._x509list[self.IP],
                        self._x509list[self.PORT],str(notAfterDate),"Correct: Certificate not expired ##Root Cert##")

    def printSigAlgoCheck(self):
        sigAlgo = bytes.decode(self._x509list[self.XOB].get_signature_algorithm())
        if not self._x509list[self.ISRT]:
            if sigAlgo in self.secureSigAlgoList:
                self.__printSigAlgoCheckFormater(self._x509list[self.IP],
                        self._x509list[self.PORT],
                        sigAlgo, "Correct: Good Signature Algorithm")
            else:
                self.__printSigAlgoCheckFormater(self._x509list[self.IP],
                        self._x509list[self.PORT],
                        sigAlgo, "\033[31mFailed: Weak Signature Algorithm\033[0m")
        else:
            if sigAlgo in self.secureSigAlgoList:
                self.__printSigAlgoCheckFormater(self._x509list[self.IP],
                        self._x509list[self.PORT],
                        sigAlgo, "Correct: Good Signature Algorithm ##Root Cert##")
            else:
                self.__printSigAlgoCheckFormater(self._x509list[self.IP],
                        self._x509list[self.PORT],
                        sigAlgo, "\033[31mFailed: Weak Signature Algorithm ##Root Cert##\033[0m")
    def printRevokedCheck(self):
        """Prints results from tuple of revoked status, Ser #, revoked reason, revoked date
        and url for CRL to RVOK index"""
        if not self._x509list[self.ISRT]:
            if not self._x509list[self.RVOK][0]:
                self.__printRevokedCheckFormater("Correct: Cert not revoked")
            else:
                self.__printRevokedCheckFormater("\033[31mFailed: Cert revoked\033[0m")
        else:
            if not self._x509list[self.RVOK][0]:
                self.__printRevokedCheckFormater("Correct: Cert not revoked ##Root Cert##")
            else:
                self.__printRevokedCheckFormater("\033[31mFailed: Cert revoked ##Root Cert##\033[0m")

################################################################################
################################################################################
######  END OF x509checks class
################################################################################
################################################################################

def certfile(arg):
    try:
        with open(arg, 'r') as txtFile:
            None
    except:
        raise argparse.ArgumentTypeError('argument must be a file')
    return arg

def getIPFromFilename(certFileName):
    """Pull IP from file name return list of IPs, slight error checking with findall ip regex
    if list of ips more than one exit with error"""
    ipCandidates=re.findall( r'[0-9]+(?:\.[0-9]+){3}', certFileName)
    if len(ipCandidates) != 1:
        print("IP parsing failure for filename: ", certFileName, " Please rename your file or use the --ipport option")
        sys.exit()
    else:
        IPfromFileName = ipCandidates[0]
    return IPfromFileName

def getPortFromFilename(certFileName, ip):
    """Pull Port from file name,
    slight error checking with isdigit() of suspected port num"""
    try:
        filenameStripped = certFileName[certFileName.find(ip) + len(ip)+1:] #should be <port>_cert.txt now
        portNum = filenameStripped[:filenameStripped.find("_")]
    except:
        print("Port number not found in filename: ",certFileName," Please rename your file or use the --ipport option")
        sys.exit()
    if portNum.isdigit():
        return portNum
    else:
        print("Port number not found in filename: ", certFileName," Please rename your file or use the --ipport option")
        sys.exit()

def pullCertsFromFile(certFileName):
    certsInFile = []
    with open(certFileName, 'r') as openCertFile:
        certFlag = False
        stringAccumulator = ''
        for line in openCertFile.readlines():
            if line == "-----BEGIN CERTIFICATE-----\n":
                certFlag = True
            if line == "-----END CERTIFICATE-----\n":
                certFlag = False
                stringAccumulator += line
                certsInFile.append(stringAccumulator)
                stringAccumulator = ''
            if certFlag:
                stringAccumulator += line
    return certsInFile

def printCNnSANResults(x509CertObjList):
    print("\033[32m" + "\n|----------------------------Begin CommonName and Subject Alternative Name Checks------------------------|\n"\
    +'{:<20}'.format("System IP:PORT") + '{:<30}'.format("CN or SAN or Err:") + '{:<20}'.format("Resolved IP") + "Result"+ "\033[0m")
    sameIPnPortFlag = None
    certChainCounter = 0
    for x in x509CertObjList:
        if sameIPnPortFlag == x.getIP() + x.getPort():
            x.printCNnSANcheck()
        else:
            if sameIPnPortFlag != None:
                print()
                certChainCounter = 0
            x.printCNnSANcheck()
            sameIPnPortFlag = x.getIP() + x.getPort()
        print("\033[34mEnd Certificate: "+ str(certChainCounter)+"\033[0m")
        certChainCounter += 1

def printPubKeyCheckResults(x509CertObjList):
    print("\033[32m" + "\n|----------------------------Begin Public Key Length Checks----------------------------------------------|\n"\
    + '{:<20}'.format("System IP:PORT")+'{:<20}'.format("Public Key Length") + '{:<20}'.format("Result") + "\033[0m")
    sameIPnPortFlag = None
    for x in x509CertObjList:
        if sameIPnPortFlag == x.getIP() + x.getPort():
            x.printPubKeyCheck()
        else:
            print() if sameIPnPortFlag != None else None
            x.printPubKeyCheck()
            sameIPnPortFlag = x.getIP() + x.getPort()

def printNotAfterCheckResults(x509CertObjList):
    print("\033[32m" + "\n|--------------------------Begin Expired/Expiring Certificate Checks-------------------------------------|\n"\
    + '{:<20}'.format("System IP:PORT")+'{:<25}'.format("Not After Date")+'{:<20}'.format("Result")+ "\033[0m")
    sameIPnPortFlag = None
    for x in x509CertObjList:
        if sameIPnPortFlag == x.getIP() + x.getPort():
            x.printNotAfterCheck()
        else:
            print() if sameIPnPortFlag != None else None
            x.printNotAfterCheck()
            sameIPnPortFlag = x.getIP() + x.getPort()

def printSigAlgoCheckResults(x509CertObjList):
    print("\033[32m" + "\n|--------------------------Begin Signature Algorithm Strength Checks-------------------------------------|\n"\
    + '{:<20}'.format("System IP:PORT")+'{:<30}'.format("Signature Algorithm")+'{:<20}'.format("Result")+ "\033[0m")
    sameIPnPortFlag = None
    for x in x509CertObjList:
        if sameIPnPortFlag == x.getIP() + x.getPort():
            x.printSigAlgoCheck()
        else:
            print() if sameIPnPortFlag != None else None
            x.printSigAlgoCheck()
            sameIPnPortFlag = x.getIP() + x.getPort()

def printRevokedCheckResults(x509CertObjList):
    print("\033[32m" + "\n|-------------------------Begin Revoked Certificate Checks-----------------------------------------------|\n"\
    + '{:<20}'.format("System IP:PORT")+'{:<20}'.format("Serial Number") + '{:<25}'.format("Revoked Reason") + '{:<25}'.format("Revoked Date") + '{:<40}'.format("Result") + '{:<20}'.format("crl URL")+ "\033[0m")
    sameIPnPortFlag = None
    for x in x509CertObjList:
        if sameIPnPortFlag == x.getIP() + x.getPort():
            x.printRevokedCheck()
        else:
            print() if sameIPnPortFlag != None else None
            x.printRevokedCheck()
            sameIPnPortFlag = x.getIP() + x.getPort()
def printWarning():
    print('\n\
           ################################################################\n\
           ################################################################\n\
           ##                                                            ##\n\
           ##     Warning: x509 extensions are pulled on a best effort   ##\n\
           ##     basis. A warning is given to manualy invistigate       ##\n\
           ##     user supplied certificates if no x509 extensions are   ##\n\
           ##     found.                                                 ##\n\
           ##     Warnings are disabled while parsing certificates in    ##\n\
           ##     the local root certificate store. These certificates   ##\n\
           ##     are older and many do not have extensions. This will   ##\n\
           ##     only affect whether a user supplied certificate is     ##\n\
           ##     identified with the ##Root Cert## flag.                ##\n\
           ##                                                            ##\n\
           ################################################################\n\
           ################################################################\n\n\
Downloading certificate revocation lists...')



def masterFunc(certFileNameList, IPnPort=None):
    printWarning()
    x509CertObjList = []
    if not IPnPort:
        for certFilename in certFileNameList:
            IPFromFilename = getIPFromFilename(certFilename)
            PortFromFilename = getPortFromFilename(certFilename, IPFromFilename)
            IPnPort = IPFromFilename +":"+ PortFromFilename
            certsFromFile = pullCertsFromFile(certFilename)
            [x509CertObjList.append(x509checks(x,IPnPort)) for x in  certsFromFile]
    else:
        certsFromFile = pullCertsFromFile(certFileNameList)
        [x509CertObjList.append(x509checks(x,IPnPort)) for x in  certsFromFile]
        
    #Get results from all x509 objects
    printCNnSANResults(x509CertObjList)
    printPubKeyCheckResults(x509CertObjList)
    printNotAfterCheckResults(x509CertObjList)
    printSigAlgoCheckResults(x509CertObjList)
    printRevokedCheckResults(x509CertObjList)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check x509 certs for security issues')
    parser.add_argument('X509certFile', type=certfile, nargs='+',
               help="Exhibit_E_client-name_ip-port_cert.txt ...")
    parser.add_argument('--ipport', nargs=1, help='Explicitly state a IP and Port <ip:port>. This option may only be used with one cert chain file.')
    args = parser.parse_args()
    if not args.ipport:
       masterFunc(args.X509certFile)
    else:
       masterFunc(args.X509certFile[0], args.ipport[0])
