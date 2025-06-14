import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import time
import re
from datetime import datetime, timezone
import requests

url = "https://android.googleapis.com/attestation/status"
timestamp = int(time.time())
headers = {"Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0"}
params = {"ts": timestamp}
with requests.get(url, headers=headers, params=params) as response:
    if response.status_code != 200:
        raise Exception(f"Error fetching data: {response.status_code}")
    crl = response.json()

class keybox:
    def __init__(self,path):
        tree = ET.parse(path)
        root = tree.getroot()

        self.number_of_pem_certificates = int(root.find('.//NumberOfCertificates').text.strip())
        pem_certificates = [cert.text.strip() for cert in root.findall('.//Certificate[@format="pem"]')[self.number_of_pem_certificates-1::-1]]

        self.oid_values = []
        self.certificate_serial_numbers = []
        self.not_valid_before = []
        self.not_valid_after = []
        self.version = []
        self.status = []

        for certificate_index in range(self.number_of_pem_certificates):
            certificate = x509.load_pem_x509_certificate(pem_certificates[certificate_index].encode(),default_backend())

            certificate_oid_values = {}
            for rdn in certificate.subject:
                certificate_oid_values[rdn.oid._name] = rdn.value
            self.oid_values.append(certificate_oid_values)

            self.certificate_serial_numbers.append(hex(certificate.serial_number)[2:].lower())
            self.not_valid_before.append(certificate.not_valid_before_utc)
            self.not_valid_after.append(certificate.not_valid_after_utc)
            self.version.append(certificate.version)
            try:
                self.status.append(crl['entries'][self.certificate_serial_numbers[certificate_index]])
            except: 
                self.status.append(None)

    def overall_status(self):
        pass

    def keychain(self):
        pass

    def root_certificate(self):
        pass


keybox = keybox(r"C:\keybox\keybox.xml")

for i in range(keybox.number_of_pem_certificates):
    print(i)
    print(keybox.oid_values[i])
    print(keybox.certificate_serial_numbers[i])
    print(keybox.not_valid_before[i])
    print(keybox.not_valid_after[i])
    print(keybox.version[i])
    print(keybox.status[i])