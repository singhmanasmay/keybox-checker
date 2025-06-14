import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import re
from datetime import datetime, timezone

class keybox:
    def __init__(self,path):
        self.tree = ET.parse(path)
        self.root = self.tree.getroot()

        self.number_of_pem_certificates = int(self.root.find('.//NumberOfCertificates').text.strip())
        self.pem_certificates = [cert.text.strip() for cert in self.root.findall('.//Certificate[@format="pem"]')[self.number_of_pem_certificates-1::-1]]
        
        self.certificate = x509.load_pem_x509_certificate(self.pem_certificates[0].encode(),default_backend())

        self.keybox_parsed = (f"{self.certificate.subject}")
        self.keybox_string = re.search(r"2\.5\.4\.5=([0-9a-fA-F]+)", self.keybox_parsed)

        self.serial_number = self.certificate.serial_number
        self.serial_number_string = hex(self.serial_number)[2:].lower()
        self.subject = self.certificate.subject
        self.not_valid_before = self.certificate.not_valid_before_utc
        self.not_valid_after = self.certificate.not_valid_after_utc
        self.current_date = datetime.now(timezone.utc)

    def oid_values(self,pem_certificate):
        certificate = x509.load_pem_x509_certificate(self.pem_certificates[pem_certificate].encode(),default_backend())

        oid_values = {}
        for rdn in certificate.subject:
            oid_values[rdn.oid._name] = rdn.value

        return oid_values

    def certificate_serial_numbers(self,pem_certificate):
        certificate = x509.load_pem_x509_certificate(self.pem_certificates[pem_certificate].encode(),default_backend())
        return hex(certificate.serial_number)[2:].lower()

    def overall_status(self):
        pass
#generator
    def status(self):
        pass

    def keychain(self):
        pass

    def certificate_values(self,pem_certificate):
        certificate = x509.load_pem_x509_certificate(self.pem_certificates[pem_certificate].encode(),default_backend())
        return certificate.not_valid_before_utc, certificate.not_valid_after_utc, certificate.version

    def root_certificate(self):
        pass

    def challenge_time(self):
        return datetime.now(timezone.utc)

keybox = keybox(r"C:\keybox\keybox.xml")

for i in range(keybox.number_of_pem_certificates):
    print(i)
    print(keybox.certificate_serial_numbers(i))
    print(keybox.challenge_time())
    for j in keybox.certificate_values(i):
        print(j)
    for j in keybox.oid_values(i):
        print(j,': ',keybox.oid_values(i)[j])
    

