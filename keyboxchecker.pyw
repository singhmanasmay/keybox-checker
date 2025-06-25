import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import time
from datetime import datetime, timezone
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
import customtkinter as ctk
import os
import winaccent
import pywinstyles
from PIL import ImageColor

root_certificates = {'Google Hardware Attestation': '-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU\nFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j\nlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y\n//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X\npXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI\nmQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB\n+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q\nuvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp\nZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7\ngLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82\nixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+\nNpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==\n-----END PUBLIC KEY-----\n',
                        'AOSP Software Attestation(EC)': '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu\nD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA==\n-----END PUBLIC KEY-----\n',
                        'AOSP Software Attestation(RSA)': '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf\nd5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg\nMdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm\n+Vfkl5YLCazOkjWFmwIDAQAB\n-----END PUBLIC KEY-----\n',  
                        'Samsung Knox Attestation': '-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA\n46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd12\n4n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBo\nZsapxB0gAOs0jSPRX5M=\n-----END PUBLIC KEY-----\n'}

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

def dark(color,factor):
    """Convert a color to a darker shade by reducing RGB values by 40%.
    
    Args:
        color: A hex color string (e.g. '#ffffff')
    
    Returns:
        A hex color string representing the darker shade
    """
    rgb = list(ImageColor.getrgb(color))
    rgb[0], rgb[1], rgb[2]= int(rgb[0]*factor), int(rgb[1]*factor), int(rgb[2]*factor)
    return '#%02x%02x%02x' % tuple(rgb)

class keybox:
    def __init__(self,path):
        tree = ET.parse(path)
        root = tree.getroot()

        self.number_of_pem_certificates = int(root.find('.//NumberOfCertificates').text.strip())
        pem_certificates = [cert.text.strip() for cert in root.findall('.//Certificate[@format="pem"]')[self.number_of_pem_certificates-1::-1]]

        self.certificate = []
        self.serial_number = []
        self.oid_values = []
        self.certificate_serial_numbers = []
        self.not_valid_before = []
        self.not_valid_after = []
        self.validity = []
        self.version = []
        self.status = []
        self.overall_status = []

        for certificate_index in range(self.number_of_pem_certificates):
            self.certificate.append(x509.load_pem_x509_certificate(pem_certificates[certificate_index].encode(),default_backend()))

            certificate_oid_values = {}
            for rdn in self.certificate[certificate_index].subject:
                certificate_oid_values[rdn.oid._name] = rdn.value
            try:
                self.serial_number.append(certificate_oid_values.pop('serialNumber'))
            except: self.serial_number.append('Software or Invalid')
            self.oid_values.append(certificate_oid_values)

            self.certificate_serial_numbers.append(hex(self.certificate[certificate_index].serial_number)[2:].lower())
            self.not_valid_before.append(self.certificate[certificate_index].not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S'))
            self.not_valid_after.append(self.certificate[certificate_index].not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S'))
            if self.certificate[certificate_index].not_valid_before_utc <= datetime.now(timezone.utc) <= self.certificate[certificate_index].not_valid_after_utc:
                self.validity.append('Valid')
            else:
                self.validity.append('Expired')
            self.version.append(self.certificate[certificate_index].version)
            try:
                self.status.append(f'{crl['entries'][self.certificate_serial_numbers[certificate_index]]['status'].title()} ({crl['entries'][self.certificate_serial_numbers[certificate_index]]['reason'].title().replace('_',' ')})')
            except: 
                self.status.append('Unrevoked')
            if self.validity[certificate_index] == 'Valid' and self.status[certificate_index] == 'Unrevoked':
                self.overall_status.append('Active')
            elif self.validity[certificate_index] == 'Expired' and self.status[certificate_index] == 'Unrevoked':
                self.overall_status.append('Expired')
            elif self.validity[certificate_index] == 'Valid' and self.status[certificate_index] != 'Unrevoked':
                self.overall_status.append('Revoked')
            else:
                self.overall_status.append('Expired and Revoked')

    def keybox_status(self):
        temp_state = []
        for state in self.overall_status:
            if state == 'Expired and Revoked':
                return state
            if state in ('Expired','Revoked'):
                if state not in temp_state:
                    temp_state.append(state)
        if len(temp_state) == 0:
            return 'Active'
        elif len(temp_state) == 1:
            return temp_state[0]
        else:
            return 'Expired and Revoked'

    def keychain(self):
        for certificate_index in range(self.number_of_pem_certificates - 1):
            issuer_certificate = self.certificate[certificate_index]
            issued_certificate = self.certificate[certificate_index + 1]

            if issued_certificate.issuer != issuer_certificate.subject:
                return 'Invalid'
            
            try:
                if issued_certificate.signature_algorithm_oid._name in ['sha256WithRSAEncryption','sha1WithRSAEncryption','sha384WithRSAEncryption','sha512WithRSAEncryption']:
                    hash_algorithm = {'sha256WithRSAEncryption': hashes.SHA256(),
                                        'sha1WithRSAEncryption': hashes.SHA1(),
                                        'sha384WithRSAEncryption': hashes.SHA384(),
                                        'sha512WithRSAEncryption': hashes.SHA512()}[issued_certificate.signature_algorithm_oid._name]
                    issuer_certificate.public_key().verify(issued_certificate.signature,issued_certificate.tbs_certificate_bytes,padding.PKCS1v15(), hash_algorithm)
                elif issued_certificate.signature_algorithm_oid._name in ['ecdsa-with-SHA256','ecdsa-with-SHA1','ecdsa-with-SHA384','ecdsa-with-SHA512']:
                    hash_algorithm = {'ecdsa-with-SHA256': hashes.SHA256(),
                                        'ecdsa-with-SHA1': hashes.SHA1(),
                                        'ecdsa-with-SHA384': hashes.SHA384(),
                                        'ecdsa-with-SHA512': hashes.SHA512()}[issued_certificate.signature_algorithm_oid._name]
                    issuer_certificate.public_key().verify(issued_certificate.signature,issued_certificate.tbs_certificate_bytes,ec.ECDSA(hash_algorithm))
                else:
                    return 'Unsupported signature algorithms'
            except Exception:
                return 'Invalid'
        return 'Valid'

    def root_certificate(self):
        root_certificate = str(self.certificate[0].public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo),'utf-8')
        for key in root_certificates:
            if root_certificates[key] == root_certificate:
                return key
        return 'Unknown/Software'
    
class gui:
    def __init__(self):
        root = ctk.CTk()
        width = 995
        height = 560
        root.geometry(f'{width}x{height}+{int((root.winfo_screenwidth()/2)-(width/2))}+{int((root.winfo_screenheight()/2)-(height/2))}')
        root.configure(fg_color='#ffffff')
        root.title('Keybox Checker')
        root.iconbitmap(os.path.join(os.path.dirname(__file__),'icon.ico'))
        ctk.set_appearance_mode("dark")

        statuslabel=ctk.CTkLabel(root,
                                height=10,
                                width=400,
                                anchor='e',
                                padx=10,
                                pady=0,
                                font=('Segoe UI',16),
                                text='juju',
                                fg_color='#000000')
        statuslabel.pack(side='bottom', fill='x')

        entryframe= ctk.CTkFrame(root,
                                border_color=winaccent.accent_normal,
                                border_width=2,
                                corner_radius=10,
                                fg_color='black')
        entryframe.pack(fill='x',side='bottom')

        self.entry= ctk.CTkEntry(entryframe,
                            text_color=winaccent.accent_normal, 
                            placeholder_text_color=winaccent.accent_normal, 
                            placeholder_text='bruh', 
                            fg_color='black', 
                            bg_color='#000001',
                            border_color='black',
                            font=('Segoe UI', 20),
                            corner_radius=10)
        self.entry.pack(side='left', fill='x', expand=True, padx=2, pady=2)
        self.entry.bind('<KeyRelease>',self.path_update)
        pywinstyles.set_opacity(self.entry, color='#000001')

        browsebutton = ctk.CTkButton(entryframe,
                                    text='Browse',
                                    width=80,
                                    height=28, 
                                    text_color='black',
                                    fg_color=winaccent.accent_normal, 
                                    corner_radius=6,
                                    hover_color=dark(winaccent.accent_normal,0.6), 
                                    font=('Segoe UI',14),
                                    command=self.browse_path)
        browsebutton.pack(side='right',anchor='s', padx=6, pady=6)

        root.mainloop()

    def browse_path(self):
        self.entry.insert(0,ctk.filedialog.askopenfilename(initialdir = "/", title = "Select a File", filetypes = (("Text files","*.txt*"),("all files","*.*"))))
        self.path_update()

    def path_update(self,x=None):
        print(self.entry.get())

gui()

keybox = keybox(r"keybox-checker\keybox\xobxes.xml")

for i in range(keybox.number_of_pem_certificates):
    print(i)
    print(f'{keybox.serial_number[i]=}')
    for key in keybox.oid_values[i]:
        print(f'{key}: {keybox.oid_values[i][key]}')
    print(f'{keybox.certificate_serial_numbers[i]=}')
    print(f'{keybox.not_valid_before[i]=}')
    print(f'{keybox.not_valid_after[i]=}')
    print(f'{keybox.validity[i]=}')
    print(f'{keybox.version[i]=}')
    print(f'{keybox.status[i]=}')
    print(f'{keybox.overall_status[i]=}')
    print()
print(f'{keybox.root_certificate()=}')
print(f'{keybox.keychain()=}')
print(f'{keybox.keybox_status()=}')