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
import functools
import threading
import multiprocessing

root_certificates = {'Google Hardware Attestation': '-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU\nFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j\nlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y\n//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X\npXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI\nmQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB\n+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q\nuvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp\nZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7\ngLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82\nixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+\nNpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==\n-----END PUBLIC KEY-----\n',
                        'AOSP Software Attestation(EC)': '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu\nD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA==\n-----END PUBLIC KEY-----\n',
                        'AOSP Software Attestation(RSA)': '-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMf\nd5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmg\nMdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm\n+Vfkl5YLCazOkjWFmwIDAQAB\n-----END PUBLIC KEY-----\n',  
                        'Samsung Knox Attestation': '-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBhbGuLrpql5I2WJmrE5kEVZOo+dgA\n46mKrVJf/sgzfzs2u7M9c1Y9ZkCEiiYkhTFE9vPbasmUfXybwgZ2EM30A1ABPd12\n4n3JbEDfsB/wnMH1AcgsJyJFPbETZiy42Fhwi+2BCA5bcHe7SrdkRIYSsdBRaKBo\nZsapxB0gAOs0jSPRX5M=\n-----END PUBLIC KEY-----\n'}

def threaded(func):
    """Decorator to automatically launch a function in a thread"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        thread.start()
        return thread
    return wrapper

def multiprocessed(func):
    """Decorator to automatically launch a function in a process"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        process = multiprocessing.Process(target=func, args=args, kwargs=kwargs)
        process.start()
        return process
    return wrapper

@threaded
def get_crl():
    global crl
    url = "https://android.googleapis.com/attestation/status"
    timestamp = int(time.time())
    headers = {"Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"}
    params = {"ts": timestamp}
    try:
        with requests.get(url, headers=headers, params=params) as response:
            crl = response.json()
    except:
        crl = None

def dark(color,brightness):
    rgb = list(ImageColor.getrgb(color))
    rgb[0], rgb[1], rgb[2]= int(rgb[0]*brightness), int(rgb[1]*brightness), int(rgb[2]*brightness)
    return '#%02x%02x%02x' % tuple(rgb)

class keybox:
    def __init__(self,path):
        self.path = path
        tree = ET.parse(self.path)
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

            if crl == None:
                self.status.append('Unable to get crl response (Please check your internet)')
            else:
                try:
                    self.status.append(f'{crl['entries'][self.certificate_serial_numbers[certificate_index]]['status'].title()} ({crl['entries'][self.certificate_serial_numbers[certificate_index]]['reason'].title().replace('_',' ')})')
                except: 
                    self.status.append('Unrevoked')

    def keybox_status(self):
        temp_state = []

        for state in self.validity:
            if state != 'Valid':
                if state not in temp_state:
                    temp_state.append(state)

        for state in self.status:
            if state != 'Unrevoked':
                if state not in temp_state:
                    temp_state.append(state)

        if len(temp_state) == 0:
            return 'Active'
        elif len(temp_state) == 1:
            return temp_state[0]
        else:
            return f'{temp_state[0]} and {temp_state[1]}'

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
    

def browse_path():
    entry.delete(0, ctk.END)
    entryframe.configure(border_color='#0096ff')
    browse_button.configure(fg_color='#0096ff',text='Browsing')
    path = ctk.filedialog.askopenfilename(initialdir=os.path.expanduser("~"),title="Select a keybox file or close this window to select a folder of keyboxes",filetypes=(("XML files", "*.xml*"), ("all files", "*.*")))
    if not path:
        path = ctk.filedialog.askdirectory(initialdir=os.path.expanduser("~"),title="Select a folder of keyboxes")
    browse_button.configure(fg_color=winaccent.accent_normal,text='Browse')
    entry.insert(0, path)
    path_update()

def path_update(x=None):
    class keybox_button:
        pass

    class certificate_label:
        pass

    keyboxes = []

    if os.path.exists(entry.get()):
        if os.path.isfile(entry.get()):
            try:
                keyboxes.append(keybox(entry.get()))
                entryframe.configure(border_color='#00ff00')
                statuslabel.configure(text='Valid keybox file',text_color='#00ff00')
            except:
                entryframe.configure(border_color='#ff0000')
                statuslabel.configure(text='Invalid keybox file',text_color='#ff0000')
        else:
            for subdir in os.listdir(entry.get()):
                if os.path.isfile(os.path.join(entry.get(),subdir)):
                    try:
                        keyboxes.append(keybox(os.path.join(entry.get(),subdir)))
                        print(subdir)
                    except: pass
            if len(keyboxes) == 0:
                entryframe.configure(border_color='#ff0000')
                statuslabel.configure(text='No valid keybox found in directory',text_color='#ff0000')
            if len(keyboxes) == 1:
                entryframe.configure(border_color='#00ff00')
                statuslabel.configure(text='1 valid keybox file found in directory',text_color='#00ff00')
            else:
                entryframe.configure(border_color='#00ff00')
                statuslabel.configure(text=f'{len(keyboxes)} valid keybox files found in directory',text_color='#00ff00')
    else:
        entryframe.configure(border_color='#ff0000')
        statuslabel.configure(text='Invalid directory',text_color='#ff0000')

get_crl()

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

entry= ctk.CTkEntry(entryframe,
                    text_color=winaccent.accent_normal, 
                    placeholder_text_color=winaccent.accent_normal, 
                    placeholder_text='bruh', 
                    fg_color='black', 
                    bg_color='#000001',
                    border_color='black',
                    font=('Segoe UI', 20),
                    corner_radius=10)
entry.pack(side='left', fill='x', expand=True, padx=2, pady=2)
entry.bind('<KeyRelease>',path_update)
pywinstyles.set_opacity(entry, color='#000001')

browse_button = ctk.CTkButton(entryframe,
                            text='Browse',
                            width=80,
                            height=28, 
                            text_color='black',
                            fg_color=winaccent.accent_normal, 
                            corner_radius=6,
                            hover_color=dark(winaccent.accent_normal,0.6), 
                            font=('Segoe UI',14),
                            command=browse_path)
browse_button.pack(side='right',anchor='s', padx=6, pady=6)

keybox_details_frame = ctk.CTkFrame(root,
                                    fg_color=dark('#00ff00',0.15)
)
keybox_details_frame.pack(side='left', fill='both', expand=True)

keybox_list_frame = ctk.CTkScrollableFrame(root,
                                    fg_color=dark('#ff0000',0.15)
)
keybox_list_frame.pack(side='right', fill='both', expand=True)

certificate_frame = ctk.CTkScrollableFrame(keybox_details_frame,
                                            fg_color='#000000'
)
certificate_frame.pack(side='left', fill='y', padx='10', pady='10')

root.mainloop()



while 'crl' not in globals():
    time.sleep(0.1)
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
    print()
print(f'{keybox.root_certificate()=}')
print(f'{keybox.keychain()=}')
print(f'{keybox.keybox_status()=}')