main_banner = """
========================================================================
|| Tool:    Certificate Provision Notifier (CerProN)                   ||
|| Author : vasolank@cisco.com                                         ||
|| Version : 1.2                                                       ||
||                                                                     ||
|| In case you have any feature request /issues, contact the author    ||
========================================================================
"""

import paramiko
from paramiko_expect import SSHClientInteraction
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
import sys
from datetime import datetime
import csv

def get_node_list():
    node_list = []
    with open ("node_list_input.txt") as fileReader:
        node_data = fileReader.read()
        node_list = node_data.splitlines()
        server_list = []
        for elem in node_list:
            server_list.append(elem.split(','))
    return server_list

def Strip_certificate_name(clioutput):
    # Function returns the certificates names on the CM in a list 
    string = clioutput.splitlines()
    i =0
    certList = []
    for line in string:
        certList.append(line.split(':')[0])
        i+=1
    return certList

def extract_cert_details(elem,cName,CertNameOutput):
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
    cert_details.append(str(serialNo))
    cert_details.append(nodeIP)
    cert_details.append(node_name)
    cert_details.append(str(certificateName))
    cert_details.append(str(beforetimeobject))
    cert_details.append(str(aftertimeobject))
    cert_details.append(cert_status)
    cert_details.append(str(expire_in))
    return cert_details


all_server = get_node_list()
print(main_banner)
print("Total nodes found:",len(all_server))
node_no = 0
failed_node = []
if node_no < len(all_server):
    filename = "Reports/Cert_report_" + str(datetime.now()).split(".")[0] + ".csv"
    modfile = filename.replace(' ','_').replace(':','_')
    with open(modfile, mode='w', newline='') as certReport:
        cert_writer = csv.writer(certReport, delimiter=',')
        cert_writer.writerow(['Serial Number','Node IP','Certificate CN','Certificate Type','Certificate Issued on','Certificate Expiry Date','Certificate Status','Will Expire In'])
        for elem in all_server:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(elem[0],username=elem[1], password=elem[2])
                print("\nConnected to node no:", node_no + 1)
                print("Fetching and analyzing certificates from node :", elem[0])
                interact = SSHClientInteraction(ssh, timeout=60, display=True)
                interact.expect('admin:')
                interact.send('set cli pagination off')
                interact.expect('admin:')
                interact.send('show cert list own')
                interact.expect('admin:')
                CertListOutput = interact.current_output_clean
                certList = Strip_certificate_name(CertListOutput)
                certList = list(filter(None,certList))
                for cert in certList:
                    interact.send('show cert own ' + cert)
                    interact.expect('admin:')
                    CertNameOutput  = interact.current_output_clean
                    cert_details = extract_cert_details(elem[0],cert,CertNameOutput)
                    cert_writer.writerow(cert_details)
                node_no += 1
            except paramiko.AuthenticationException:
                print("\nAuthentication failed for node: ",elem[0],". Please check the credentials in input file")
                failed_node.append(elem[0])
            except paramiko.SSHException as SSHException:
                print("\nUnable to establish a SSH connection: ", SSHException)
                print("connection failed for node:",elem[0])
                failed_node.append(elem[0])
            except Exception as E:
                print("\nError occured: ", E)
                print("connection failed for node:",elem[0])
                failed_node.append(elem[0])
            
        if  node_no == len(all_server):
            if len(failed_node) == 0:         
                print("\n\n")
                print("########################################################################")
                print("Program completed successfully, please check the report in the directory")
                print("########################################################################")
                input()
        else:
            cert_writer.writerow(" ")
            cert_writer.writerow(['Failed Nodes'])
            for item in failed_node:
                cert_writer.writerow([item])
            print("\n\n")
            print("********************************************************************************")
            print("This run was partially successful. Please check the reports for the failed nodes")
            print("********************************************************************************")
            input()