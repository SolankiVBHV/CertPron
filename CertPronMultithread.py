import threading
import paramiko
from paramiko_expect import SSHClientInteraction
from OpenSSL import crypto
import csv
import numpy as np
import pandas as pd
import glob
import os
from datetime import datetime
import re
from dateutil import parser
from dateutil.tz import UTC


class CertificateActions():
    def __init__(self):
        super().__init__()
    
    def get_node_list(self):
        node_list = []
        with open("runAgain.txt") as fileReader:
            node_data = fileReader.read()
            node_list = node_data.splitlines()
            server_list = []
            for elem in node_list:
                server_list.append(elem.split(','))
        return server_list

    def convertTimetoUTC(self, inTime):
        timezone_info = {
            "A": 1 * 3600,
            "ACDT": 10.5 * 3600,
            "ACST": 9.5 * 3600,
            "ACT": -5 * 3600,
            "ACWST": 8.75 * 3600,
            "ADT": 4 * 3600,
            "AEDT": 11 * 3600,
            "AEST": 10 * 3600,
            "AET": 10 * 3600,
            "AFT": 4.5 * 3600,
            "AKDT": -8 * 3600,
            "AKST": -9 * 3600,
            "ALMT": 6 * 3600,
            "AMST": -3 * 3600,
            "AMT": -4 * 3600,
            "ANAST": 12 * 3600,
            "ANAT": 12 * 3600,
            "AQTT": 5 * 3600,
            "ART": -3 * 3600,
            "AST": 3 * 3600,
            "AT": -4 * 3600,
            "AWDT": 9 * 3600,
            "AWST": 8 * 3600,
            "AZOST": 0 * 3600,
            "AZOT": -1 * 3600,
            "AZST": 5 * 3600,
            "AZT": 4 * 3600,
            "AoE": -12 * 3600,
            "B": 2 * 3600,
            "BNT": 8 * 3600,
            "BOT": -4 * 3600,
            "BRST": -2 * 3600,
            "BRT": -3 * 3600,
            "BST": 6 * 3600,
            "BTT": 6 * 3600,
            "C": 3 * 3600,
            "CAST": 8 * 3600,
            "CAT": 2 * 3600,
            "CCT": 6.5 * 3600,
            "CDT": -5 * 3600,
            "CEST": 2 * 3600,
            "CET": 1 * 3600,
            "CHADT": 13.75 * 3600,
            "CHAST": 12.75 * 3600,
            "CHOST": 9 * 3600,
            "CHOT": 8 * 3600,
            "CHUT": 10 * 3600,
            "CIDST": -4 * 3600,
            "CIST": -5 * 3600,
            "CKT": -10 * 3600,
            "CLST": -3 * 3600,
            "CLT": -4 * 3600,
            "COT": -5 * 3600,
            "CST": -6 * 3600,
            "CT": -6 * 3600,
            "CVT": -1 * 3600,
            "CXT": 7 * 3600,
            "ChST": 10 * 3600,
            "D": 4 * 3600,
            "DAVT": 7 * 3600,
            "DDUT": 10 * 3600,
            "E": 5 * 3600,
            "EASST": -5 * 3600,
            "EAST": -6 * 3600,
            "EAT": 3 * 3600,
            "ECT": -5 * 3600,
            "EDT": -4 * 3600,
            "EEST": 3 * 3600,
            "EET": 2 * 3600,
            "EGST": 0 * 3600,
            "EGT": -1 * 3600,
            "EST": -5 * 3600,
            "ET": -5 * 3600,
            "F": 6 * 3600,
            "FET": 3 * 3600,
            "FJST": 13 * 3600,
            "FJT": 12 * 3600,
            "FKST": -3 * 3600,
            "FKT": -4 * 3600,
            "FNT": -2 * 3600,
            "G": 7 * 3600,
            "GALT": -6 * 3600,
            "GAMT": -9 * 3600,
            "GET": 4 * 3600,
            "GFT": -3 * 3600,
            "GILT": 12 * 3600,
            "GMT": 0 * 3600,
            "GST": 4 * 3600,
            "GYT": -4 * 3600,
            "H": 8 * 3600,
            "HDT": -9 * 3600,
            "HKT": 8 * 3600,
            "HOVST": 8 * 3600,
            "HOVT": 7 * 3600,
            "HST": -10 * 3600,
            "I": 9 * 3600,
            "ICT": 7 * 3600,
            "IDT": 3 * 3600,
            "IOT": 6 * 3600,
            "IRDT": 4.5 * 3600,
            "IRKST": 9 * 3600,
            "IRKT": 8 * 3600,
            "IRST": 3.5 * 3600,
            "IST": 5.5 * 3600,
            "JST": 9 * 3600,
            "K": 10 * 3600,
            "KGT": 6 * 3600,
            "KOST": 11 * 3600,
            "KRAST": 8 * 3600,
            "KRAT": 7 * 3600,
            "KST": 9 * 3600,
            "KUYT": 4 * 3600,
            "L": 11 * 3600,
            "LHDT": 11 * 3600,
            "LHST": 10.5 * 3600,
            "LINT": 14 * 3600,
            "M": 12 * 3600,
            "MAGST": 12 * 3600,
            "MAGT": 11 * 3600,
            "MART": 9.5 * 3600,
            "MAWT": 5 * 3600,
            "MDT": -6 * 3600,
            "MHT": 12 * 3600,
            "MMT": 6.5 * 3600,
            "MSD": 4 * 3600,
            "MSK": 3 * 3600,
            "MST": -7 * 3600,
            "MT": -7 * 3600,
            "MUT": 4 * 3600,
            "MVT": 5 * 3600,
            "MYT": 8 * 3600,
            "N": -1 * 3600,
            "NCT": 11 * 3600,
            "NDT": 2.5 * 3600,
            "NFT": 11 * 3600,
            "NOVST": 7 * 3600,
            "NOVT": 7 * 3600,
            "NPT": 5.5 * 3600,
            "NRT": 12 * 3600,
            "NST": 3.5 * 3600,
            "NUT": -11 * 3600,
            "NZDT": 13 * 3600,
            "NZST": 12 * 3600,
            "O": -2 * 3600,
            "OMSST": 7 * 3600,
            "OMST": 6 * 3600,
            "ORAT": 5 * 3600,
            "P": -3 * 3600,
            "PDT": -7 * 3600,
            "PET": -5 * 3600,
            "PETST": 12 * 3600,
            "PETT": 12 * 3600,
            "PGT": 10 * 3600,
            "PHOT": 13 * 3600,
            "PHT": 8 * 3600,
            "PKT": 5 * 3600,
            "PMDT": -2 * 3600,
            "PMST": -3 * 3600,
            "PONT": 11 * 3600,
            "PST": -8 * 3600,
            "PT": -8 * 3600,
            "PWT": 9 * 3600,
            "PYST": -3 * 3600,
            "PYT": -4 * 3600,
            "Q": -4 * 3600,
            "QYZT": 6 * 3600,
            "R": -5 * 3600,
            "RET": 4 * 3600,
            "ROTT": -3 * 3600,
            "S": -6 * 3600,
            "SAKT": 11 * 3600,
            "SAMT": 4 * 3600,
            "SAST": 2 * 3600,
            "SBT": 11 * 3600,
            "SCT": 4 * 3600,
            "SGT": 8 * 3600,
            "SRET": 11 * 3600,
            "SRT": -3 * 3600,
            "SST": -11 * 3600,
            "SYOT": 3 * 3600,
            "T": -7 * 3600,
            "TAHT": -10 * 3600,
            "TFT": 5 * 3600,
            "TJT": 5 * 3600,
            "TKT": 13 * 3600,
            "TLT": 9 * 3600,
            "TMT": 5 * 3600,
            "TOST": 14 * 3600,
            "TOT": 13 * 3600,
            "TRT": 3 * 3600,
            "TVT": 12 * 3600,
            "U": -8 * 3600,
            "ULAST": 9 * 3600,
            "ULAT": 8 * 3600,
            "UTC": 0 * 3600,
            "UYST": -2 * 3600,
            "UYT": -3 * 3600,
            "UZT": 5 * 3600,
            "V": -9 * 3600,
            "VET": -4 * 3600,
            "VLAST": 11 * 3600,
            "VLAT": 10 * 3600,
            "VOST": 6 * 3600,
            "VUT": 11 * 3600,
            "W": -10 * 3600,
            "WAKT": 12 * 3600,
            "WARST": -3 * 3600,
            "WAST": 2 * 3600,
            "WAT": 1 * 3600,
            "WEST": 1 * 3600,
            "WET": 0 * 3600,
            "WFT": 12 * 3600,
            "WGST": -2 * 3600,
            "WGT": -3 * 3600,
            "WIB": 7 * 3600,
            "WIT": 9 * 3600,
            "WITA": 8 * 3600,
            "WST": 14 * 3600,
            "WT": 0 * 3600,
            "X": -11 * 3600,
            "Y": -12 * 3600,
            "YAKST": 10 * 3600,
            "YAKT": 9 * 3600,
            "YAPT": 10 * 3600,
            "YEKST": 6 * 3600,
            "YEKT": 5 * 3600,
            "Z": 0 * 3600,
        }
        timestamp = parser.parse(inTime, tzinfos=timezone_info)
        UTCtime = timestamp.astimezone(UTC)
        return UTCtime

    def strip_certificate_name(self, certificateOutput):
        string = certificateOutput.splitlines()
        i =0
        certList = []
        for line in string:
            certList.append(line.split(':')[0])
            i+=1
        return certList
    
    def extract_cert_details(self, region, clTag, elem,cName,CertNameOutput):
        '''Returns a list of certificate details as a list'''
        end_cert = CertNameOutput.split('-----BEGIN CERTIFICATE-----')[1]
        start_cert = "-----BEGIN CERTIFICATE-----"
        comp_cert = start_cert + end_cert
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, comp_cert)
        nodeIP = elem
        certificateName = cName
        cert_details = []
        serialNo = cert.get_serial_number()
        object509 = cert.get_issuer()
        node_name = object509.CN
        beforetime = str(cert.get_notBefore())
        beforetimeobject = datetime.strptime(beforetime,'b\'%Y%m%d%H%M%SZ\'')
        aftertime = str(cert.get_notAfter())
        aftertimeobject = datetime.strptime(aftertime,'b\'%Y%m%d%H%M%SZ\'')
        currentTime = datetime.now()
        expire_in = aftertimeobject - currentTime

        cert_status = ''
        if cert.has_expired():
            cert_status = "EXPIRED"
        else:
            cert_status = "VALID"
        cert_details.append(str(region))
        cert_details.append(str(clTag))
        cert_details.append(str(serialNo))
        cert_details.append(str(nodeIP))
        cert_details.append(str(node_name))
        cert_details.append(str(certificateName))
        cert_details.append(str(beforetimeobject))
        cert_details.append(str(aftertimeobject))
        cert_details.append(str(cert_status))
        cert_details.append(str(expire_in))
        return cert_details

    def regex_extract_cert_details(self, region, clTag, elem, cName, CertNameOutput):
        mainPattern = re.compile("Serial Number: (?P<SerialNo>\w+)|Validity From: (?P<Valid>.+?)\n|To:\s+(?P<Exp>.+?)\n")
        res = re.findall(mainPattern, CertNameOutput)
        serialNumber = res[0][0]
        validDate = res[1][1]
        expiryDate = res[2][2]
        # getting CN
        cnPattern = re.compile("CN=(.+?),")
        cnPattern1 = re.compile("CN=(.+?)\n")
        res3 = re.search(cnPattern, CertNameOutput)
        if res3 == None:
            res3 = re.search(cnPattern1, CertNameOutput)
        CN = res3.groups()[0]

        validUTC = self.convertTimetoUTC(validDate)
        expiryUTC = self.convertTimetoUTC(expiryDate)
        state = ''
        timeDelta = expiryUTC - validUTC
        td = int(str(timeDelta).split()[0])
        if td <= 0: state = 'Expired'
        else: state = 'Valid'

        cert_detail = []
        cert_detail.append(str(region))
        cert_detail.append(str(clTag))
        cert_detail.append(serialNumber)
        cert_detail.append(elem)
        cert_detail.append((str(CN)))
        cert_detail.append(validDate)
        cert_detail.append(expiryDate)
        cert_detail.append(state)
        cert_detail.append(td)
        return cert_detail


    def main_function(self,node_details):
        failed_node = []
        filename = "Reports/Cert_report_"+ str(datetime.now().strftime("%Y-%m-%d")).split(".")[0] + ".txt"
        modfile = filename.replace(' ','_').replace(':','_')
        errorFileName = "Reports/Error_report" + str(datetime.now().strftime("%Y-%m-%d")).split(".")[0] + ".txt"
        modErrorFileName = errorFileName.replace(':', '_')
        with open(modfile, mode='a', newline='') as certReport, open(modErrorFileName, mode='a', newline='') as errorReport:
            try:
                cert_writer = csv.writer(certReport, delimiter=',')
                error_writer = csv.writer(errorReport, delimiter=',')
                print("running for:", node_details[2])
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(node_details[3], username=node_details[4], password=node_details[5])
                interact = SSHClientInteraction(ssh, timeout=60, display=True)
                interact.expect('admin:')
                interact.send('set cli pagination off')
                interact.expect('admin:')
                interact.send('show cert list own')
                interact.expect('admin:')
                CertListOutput = interact.current_output_clean
                certList = self.strip_certificate_name(CertListOutput)
                certList = list(filter(None,certList))
                for cert in certList:
                    interact.send('show cert own ' + cert)
                    interact.expect('admin:')
                    CertNameOutput  = interact.current_output_clean
                    cert_details = self.extract_cert_details(node_details[0], node_details[1],node_details[2], cert, CertNameOutput)
                    cert_writer.writerow(cert_details)

                # # trust certs
                # interact.send('show cert list trust')
                # interact.expect('admin:')
                # TrustCertListOutput = interact.current_output_clean
                # TrustCertList = self.strip_certificate_name(TrustCertListOutput)
                # TrustCertList = list(filter(None,TrustCertList))
                # for cert in TrustCertList:
                #     interact.send('show cert trust ' + cert)
                #     interact.expect('admin:')
                #     TrustCertNameOutput  = interact.current_output_clean
                #     TrustCert_details = self.regex_extract_cert_details(node_details[0], node_details[1],node_details[2], cert, TrustCertNameOutput)
                #     cert_writer.writerow(TrustCert_details)
            except paramiko.AuthenticationException:
                print("\nAuthentication failed for node: ", node_details[2], ". Please check the credentials in input file")
                failed_node.append(node_details[2])
            except paramiko.SSHException as SSHException:
                print("\nUnable to establish a SSH connection: ", SSHException)
                print("connection failed for node:",node_details[2])
                failed_node.append(node_details[2])
            except Exception as E:
                print("\nError occurred: ", E)
                print("connection failed for node:",node_details[2])
                failed_node.append(node_details[2])
                #failed node info
            finally:
                for item in failed_node:
                    error_writer.writerow([item])


def runner():
    certObj = CertificateActions()
    all_server = certObj.get_node_list()
    threads = []
    for h in all_server:
        t = threading.Thread(target=certObj.main_function, args=(h,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


def createReport():
    list_of_files = glob.glob('Reports/Cer*.txt')
    latest_file = max(list_of_files, key=os.path.getctime)
    print(latest_file)
    df = pd.read_csv(latest_file, sep=',',
                     names=['Region','Cluster Tag', 'Serial Number', 'Node IP', 'Certificate CN', 'Certificate Type',
                            'Certificate Issued on', 'Certificate Expiry Date', 'Certificate Status', 'Will Expire In'])
    # getting days from expiry time and adding a new column
    df['Expire In Days'] = df['Will Expire In'].str.split(n=0, expand=True)[0]
    df['Expire In Days'] = df['Expire In Days'].apply(int)

    conditions = [
        (((df['Expire In Days']) <= 0),
        (df['Expire In Days']) <= 10),
        ((df['Expire In Days']) > 10) & ((df['Expire In Days']) <= 30),
        ((df['Expire In Days']) > 30) & ((df['Expire In Days']) <= 60),
        ((df['Expire In Days']) > 60) & ((df['Expire In Days']) <= 90),
        ((df['Expire In Days']) > 90)
    ]

    values = ['Expired-needs cleanup/regeneration','Immediate[10 days]', 'In Next 30 days', 'In Next 60 days', 'In Next 90 days', 'After 90 days']

    df['Action Needed In'] = np.select(conditions, values)

    df['Team'] = np.where(df['Action Needed In'] == 'Immediate[10 days]', "Operate", "Operate & CSR")

    """pivot table- works but doesnt look good """
    """
    table = pd.pivot_table(df, index=['Cluster Tag'],
                           values = ["Serial Number"],
                           aggfunc=[np.count_nonzero])
    """

    ReportFilename = ("Reports/Cert_report_" + str(datetime.now()).split(".")[0] + ".xlsx").replace(' ', '_').replace(
        ':', '_')

    writer = pd.ExcelWriter(ReportFilename, engine="xlsxwriter")
    df.to_excel(writer, sheet_name='Data', index=False)
    writer.save()


start_time = datetime.now()
runner()
createReport()
end_time = datetime.now()
print('Duration: {}'.format(end_time - start_time))
