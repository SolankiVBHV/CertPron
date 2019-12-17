from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
import sys
from datetime import datetime
import csv
import pprint

string = """[
  Version: V3
  Serial Number: 523C32C09694B0A60168D6EE36A3B96E
  SignatureAlgorithm: SHA1withRSA (1.2.840.113549.1.1.5)
  Issuer Name: L=GB, ST=LN, CN=HSBC-LAB-GBCUC01-PUB, OU=LAB, O=HSBC, C=GB
  Validity From: Sun Jul 08 13:05:19 BST 2018
           To:   Fri Jul 07 13:05:18 BST 2023
  Subject Name: L=GB, ST=LN, CN=HSBC-LAB-GBCUC01-PUB, OU=LAB, O=HSBC, C=GB
  Key: RSA (1.2.840.113549.1.1.1)
    Key value: 3082010a0282010100c17cde47204921b418a0ebec6978f0b53f8a3f6781084561da71b376b0825b6e794e1eb53668280f731af0001afe4baeedf58f6c81612192111789a2e0740fc6ecf4e267b8207372cb4b9b25107ff432b92ab37e13c8175ee72b6b24a47e5defc9dd47d98a3fe9dac0f4e1b7dac071e0746d039acb658e959bdcb1de573051d524a92063be983f2729974f3a90e1e96959e4f55c66bd187c943760d92ce026544bd8b241952a4f3ba1bd8be4bea3bc447a8b79533a69b1398341690e30792d78b7099a1803cd14a779fb4aa32354cacc5ff99e376ba4bf76c8e3fa722edf4f92882225b52b78caa6691f41f411b689b61c2c5d505eb9233a07e33100567fb2730203010001
  Extensions: 3 present
  [
     Extension: KeyUsage (OID.2.5.29.15)
     Critical: false
     Usages: digitalSignature, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign,
  ]
  [
     Extension: ExtKeyUsageSyntax (OID.2.5.29.37)
     Critical: false
     Usage oids: 1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2, 1.3.6.1.5.5.7.3.5,
  ]
  [
     Extension: SubjectKeyIdentifier (OID.2.5.29.14)
     Critical: false
     keyID: bb77bc184dbbc0b28335125dd4bc82689432b518
  ]

  Signature:
  0000: 38 8f 5a 00 77 00 b1 f5 b2 49 83 73 5c 64 e0 54 [8.Z.w....I.s\d.T]
  0010: 61 34 4b 12 fe 4b aa 0b fc 96 3f 27 b4 66 19 ae [a4K..K....?'.f..]
  0020: 5d 22 31 72 13 56 86 bc f6 cd 5c 45 72 61 ed 01 []"1r.V....\Era..]
  0030: d4 46 df 8b 39 93 31 05 86 c9 9f 7c eb 38 65 c9 [.F..9.1....|.8e.]
  0040: ed e6 e3 f8 94 47 28 44 30 db 70 c1 e4 39 90 38 [.....G(D0.p..9.8]
  0050: d0 ca b3 46 cd d8 27 58 c4 78 7f 9f 3f 4f c3 bc [...F..'X.x..?O..]
  0060: 91 3e af 86 52 0c 70 28 66 76 57 fd 58 80 e5 dd [.>..R.p(fvW.X...]
  0070: d4 5b 71 20 ca 2c ba a8 88 46 0e 95 eb 1f d4 ff [.[q .,...F......]
  0080: 47 f0 d5 e7 6c d9 42 be b2 e6 8d 6f c3 6c f9 26 [G...l.B....o.l.&]
  0090: 0d 65 ed 4b 9d 16 32 83 01 a4 7a bb 10 b1 dc 54 [.e.K..2...z....T]
  00a0: 66 b4 ff 1f 90 54 70 84 6e de 97 29 e5 2a fa d7 [f....Tp.n..).*..]
  00b0: 0b 3e 14 b5 39 8a 57 91 2c ec e2 d0 66 51 2a 22 [.>..9.W.,...fQ*"]
  00c0: 0c 19 a0 64 5d 7b 02 3a 05 99 c3 d0 d3 e2 22 19 [...d]{.:......".]
  00d0: 5c c5 e5 63 0f 9b dc b5 08 62 03 2d a9 d4 25 68 [\..c.....b.-..%h]
  00e0: 5d ad 5e 2d af 82 43 15 de 26 3a a6 e7 9d 9d cc [].^-..C..&:.....]
  00f0: 7a d5 0d a6 27 85 56 63 7e 88 ff 0b d0 59 06 b9 [z...'.Vc~....Y..]

]-----BEGIN CERTIFICATE-----
MIIDpzCCAo+gAwIBAgIQUjwywJaUsKYBaNbuNqO5bjANBgkqhkiG9w0BAQUFADBj
MQswCQYDVQQGEwJHQjENMAsGA1UECgwESFNCQzEMMAoGA1UECwwDTEFCMR0wGwYD
VQQDDBRIU0JDLUxBQi1HQkNVQzAxLVBVQjELMAkGA1UECAwCTE4xCzAJBgNVBAcM
AkdCMB4XDTE4MDcwODEyMDUxOVoXDTIzMDcwNzEyMDUxOFowYzELMAkGA1UEBhMC
R0IxDTALBgNVBAoMBEhTQkMxDDAKBgNVBAsMA0xBQjEdMBsGA1UEAwwUSFNCQy1M
QUItR0JDVUMwMS1QVUIxCzAJBgNVBAgMAkxOMQswCQYDVQQHDAJHQjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMF83kcgSSG0GKDr7Gl48LU/ij9ngQhF
Ydpxs3awgltueU4etTZoKA9zGvAAGv5Lru31j2yBYSGSEReJouB0D8bs9OJnuCBz
cstLmyUQf/QyuSqzfhPIF17nK2skpH5d78ndR9mKP+nawPTht9rAceB0bQOay2WO
lZvcsd5XMFHVJKkgY76YPycpl086kOHpaVnk9VxmvRh8lDdg2SzgJlRL2LJBlSpP
O6G9i+S+o7xEeot5UzppsTmDQWkOMHkteLcJmhgDzRSneftKoyNUysxf+Z43a6S/
dsjj+nIu30+SiCIltSt4yqZpH0H0EbaJthwsXVBeuSM6B+MxAFZ/snMCAwEAAaNX
MFUwCwYDVR0PBAQDAgK8MCcGA1UdJQQgMB4GCCsGAQUFBwMBBggrBgEFBQcDAgYI
KwYBBQUHAwUwHQYDVR0OBBYEFLt3vBhNu8CygzUSXdS8gmiUMrUYMA0GCSqGSIb3
DQEBBQUAA4IBAQA4j1oAdwCx9bJJg3NcZOBUYTRLEv5Lqgv8lj8ntGYZrl0iMXIT
Voa89s1cRXJh7QHURt+LOZMxBYbJn3zrOGXJ7ebj+JRHKEQw23DB5DmQONDKs0bN
2CdYxHh/nz9Pw7yRPq+GUgxwKGZ2V/1YgOXd1FtxIMosuqiIRg6V6x/U/0fw1eds
2UK+suaNb8Ns+SYNZe1LnRYygwGkersQsdxUZrT/H5BUcIRu3pcp5Sr61ws+FLU5
ileRLOzi0GZRKiIMGaBkXXsCOgWZw9DT4iIZXMXlYw+b3LUIYgMtqdQlaF2tXi2v
gkMV3iY6puedncx61Q2mJ4VWY36I/wvQWQa5
-----END CERTIFICATE-----"""

end_cert = string.split('-----BEGIN CERTIFICATE-----')[1]
start_cert = "-----BEGIN CERTIFICATE-----"
comp_cert = start_cert + end_cert
#print(comp_cert)

cert_details = []
cert = crypto.load_certificate(crypto.FILETYPE_PEM, comp_cert)

#certsubject = crypto.X509Name

serialNo = cert.get_serial_number()
#print(type(serialNo))
object509 = cert.get_issuer()
nodeName = object509.CN
#print(type(nodeName))
#time
beforetime = str(cert.get_notBefore())
beforetimeobject = datetime.strptime(beforetime,'b\'%Y%m%d%H%M%SZ\'')
currentTime = datetime.now()
aftertime = str(cert.get_notAfter())
aftertimeobject = datetime.strptime(aftertime,'b\'%Y%m%d%H%M%SZ\'')
ExpiryDate = str(aftertimeobject)
expire_in = aftertimeobject - currentTime
print("Certificate will expire in : ", expire_in)

certStatus = ''
if cert.has_expired():
    certStatus = 'EXPIRED'
else:
    certStatus = 'VALID'

cert_details.append(str(serialNo))
cert_details.append(nodeName)
cert_details.append(str(beforetimeobject))
cert_details.append(ExpiryDate)
cert_details.append(certStatus)
print(cert_details)

filename = "Reports/Cert_report_" + str(datetime.now()).split(".")[0] + ".csv"
modfile = filename.replace(' ','_').replace(':','_')
with open(modfile, mode='w', newline='') as certReport:
   cert_writer = csv.writer( certReport, delimiter=',')
   cert_writer.writerow(['Serial Number','Node Name','Certificate Issued on','Certificate Expiry Date','Certificate Status'])
   cert_writer.writerow(cert_details)