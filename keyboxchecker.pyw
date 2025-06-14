import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import re
from datetime import datetime, timezone

class keybox:
    def __init__(self,path):
        tree = ET.parse(path)
        root = tree.getroot()

        number_of_pem_certificates = int(root.find('.//NumberOfCertificates').text.strip())
        pem_certificates = [cert.text.strip() for cert in root.findall('.//Certificate[@format="pem"]')[number_of_pem_certificates-1::-1]]

        self.oid_values = []
        self.certificate_serial_numbers = []
        self.not_valid_before = []
        self.not_valid_after = []
        self.version = []
        self.status = []

        for certificate_index in range(number_of_pem_certificates):
            certificate = x509.load_pem_x509_certificate(pem_certificates[certificate_index].encode(),default_backend())

            certificate_oid_values = {}
            for rdn in certificate.subject:
                certificate_oid_values[rdn.oid._name] = rdn.value
            self.oid_values += certificate_oid_values

            self.certificate_serial_numbers += hex(certificate.serial_number)[2:].lower()
            self.not_valid_before += certificate.not_valid_before_utc
            self.not_valid_after += certificate.not_valid_after_utc
            self.version += certificate.version



    def overall_status(self):
        pass

    def keychain(self):
        pass

    def root_certificate(self):
        pass


keybox = keybox(r"C:\keybox\keybox.xml")

for i in range(keybox.number_of_pem_certificates):
    print(i)
    print(keybox.certificate_serial_numbers(i))
    print(keybox.challenge_time())
    for j in keybox.certificate_values(i):
        print(j)
    for j in keybox.oid_values(i):
        print(j,': ',keybox.oid_values(i)[j])
    

