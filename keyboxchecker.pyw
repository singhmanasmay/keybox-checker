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
        self.certificate_info =[]

        for certificate_index in range(self.number_of_pem_certificates):
            self.certificate_info.append({})
            self.certificate.append(x509.load_pem_x509_certificate(pem_certificates[certificate_index].encode(),default_backend()))

            self.certificate_info[certificate_index]['Certificate Serial Number'] = hex(self.certificate[certificate_index].serial_number)[2:].lower()

            self.certificate_info[certificate_index]['Not Valid Before'] = self.certificate[certificate_index].not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S')

            self.certificate_info[certificate_index]['Not Valid After'] = self.certificate[certificate_index].not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S')

            if self.certificate[certificate_index].not_valid_before_utc <= datetime.now(timezone.utc) <= self.certificate[certificate_index].not_valid_after_utc:
                self.certificate_info[certificate_index]['Validity'] = 'Valid'
            else:
                self.certificate_info[certificate_index]['Validity'] = 'Expired'

            self.certificate_info[certificate_index]['Encryption Algorithm'] = self.certificate[certificate_index].signature_algorithm_oid._name

            if crl == None:
                self.certificate_info[certificate_index]['Status'] = 'Unable to get crl response (Please check your internet)'
            else:
                try:
                    self.certificate_info[certificate_index]['Status'] = f'{crl['entries'][self.certificate_info[certificate_index]['Certificate Serial Number']]['status'].title()} ({crl['entries'][self.certificate_info[certificate_index]['Certificate Serial Number']]['reason'].title().replace('_',' ')})'
                except: 
                    self.certificate_info[certificate_index]['Status'] = 'Unrevoked'

            certificate_oid_values = {}
            for rdn in self.certificate[certificate_index].subject:
                certificate_oid_values[rdn.oid._name] = rdn.value
            if 'serialNumber' not in certificate_oid_values:
                certificate_oid_values['Serial Number'] = 'Software or Invalid'
            else:
                certificate_oid_values['Serial Number'] = certificate_oid_values.pop('serialNumber')
            self.certificate_info[certificate_index].update(certificate_oid_values)

    def keybox_status(self):
        temp_state = []

        for dict in self.certificate_info:
            if dict['Validity'] != 'Valid':
                if dict['Validity'] not in temp_state:
                    temp_state.append(dict['Validity'])

        for dict in self.certificate_info:
            if dict['Status'] != 'Unrevoked':
                if dict['Status'] not in temp_state:
                    temp_state.append(dict['Status'])

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

@threaded
def path_update(x=None):
    class keybox_button(ctk.CTkButton):
        def __init__(self,keybox):
            self.keybox = keybox
            if self.keybox.keybox_status() == 'Active' and keybox.keychain() == 'Valid':
                self.button_color = '#7CFC00'
            else:
                self.button_color = '#ff0000'
            super().__init__(master=keybox_list_frame,
                            bg_color = '#000000',
                            text = f'{os.path.basename(self.keybox.path)}',
                            text_color=self.button_color,
                            anchor='w',
                            width=999999,
                            fg_color = dark(self.button_color,0.2),
                            hover_color=dark(self.button_color,0.4),
                            command=self.show_keybox_details)
            self.pack(side='top',fill='both',expand=True,padx=5,pady=5)

        def show_keybox_details(self):
            certificate_frame.pack(side='left', fill='y', padx=10, pady=10)
            keybox_details_label.pack(side='right', fill='both', expand=True, pady=10)
            keybox_details_frame.configure(fg_color=dark(self.button_color,0.2))
            keybox_details_label.configure(text_color=self.button_color,text=f'Path: {self.keybox.path}\nKeychain: {self.keybox.keychain()}\nRoot Certificate: {self.keybox.root_certificate()}\nKeybox Status: {self.keybox.keybox_status()}')
            certificate_chain_label = ctk.CTkLabel(master=certificate_frame,
                                                    bg_color= '#000000',
                                                    text='Certificate Keychain:',
                                                    text_color='#ffffff',
                                                    anchor='w',
                                                    justify='left',
                                                    width=999999,
                                                    fg_color='#000000',
                                                    corner_radius=6)
            certificate_chain_label.pack(side='top',fill='both',expand=True)

            class certificate_label(ctk.CTkLabel):
                def __init__(self,dict):
                    if dict['Validity'] == 'Valid' and dict['Status'] == 'Unrevoked':
                        label_color = '#7CFC00'
                    else:
                        label_color = '#ff0000'
                    text = '\n'
                    for key in dict:
                        text += f'{key}: {dict[key]}\n'
                    super().__init__(master=certificate_frame,
                                        bg_color= '#000000',
                                        text=text,
                                        text_color=label_color,
                                        anchor='w',
                                        justify='left',
                                        width=999999,
                                        fg_color=dark(label_color,0.2),
                                        corner_radius=6)
                    self.pack(side='top',fill='both',expand=True,padx=5,pady=5)

            for dict in self.keybox.certificate_info:
                globals()[dict['Serial Number']] = certificate_label(dict)

    status_temp = statuslabel.cget('text')
    if 'crl' not in globals():
        statuslabel.configure(text='Fetching CRL data, please wait...',text_color='#7CFC00')
    while 'crl' not in globals():
        time.sleep(0.5)
    statuslabel.configure(text=status_temp)

    keyboxes = []
    if os.path.exists(entry.get()):
        if os.path.isfile(entry.get()):
            try:
                keyboxes.append(keybox(entry.get()))
                entryframe.configure(border_color='#7CFC00')
                statuslabel.configure(text='Valid keybox file',text_color='##7CFC00')
            except:
                entryframe.configure(border_color='#ff0000')
                statuslabel.configure(text='Invalid keybox file',text_color='#ff0000')
        else:
            for subdir in os.listdir(entry.get()):
                if os.path.isfile(os.path.join(entry.get(),subdir)):
                    try:
                        keyboxes.append(keybox(os.path.join(entry.get(),subdir)))
                    except: pass
            if len(keyboxes) == 0:
                entryframe.configure(border_color='#ff0000')
                statuslabel.configure(text='No valid keybox found in directory',text_color='#ff0000')
            if len(keyboxes) == 1:
                entryframe.configure(border_color='#7CFC00')
                statuslabel.configure(text='1 valid keybox file found in directory',text_color='#7CFC00')
            else:
                entryframe.configure(border_color='#7CFC00')
                statuslabel.configure(text=f'{len(keyboxes)} valid keybox files found in directory',text_color='#7CFC00')
    else:
        entryframe.configure(border_color='#ff0000')
        statuslabel.configure(text='Invalid directory',text_color='#ff0000')
    
    for keybox_ in keyboxes:
        globals()[keybox_.path] = keybox_button(keybox_)


get_crl()

root = ctk.CTk()
width = 995
height = 560
root.geometry(f'{width}x{height}+{int((root.winfo_screenwidth()/2)-(width/2))}+{int((root.winfo_screenheight()/2)-(height/2))}')
root.configure(fg_color="#000000")
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
                        text='',
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
                    placeholder_text='Input or browse a keybox file or folder path', 
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
                                    fg_color='#000000',
                                    )
keybox_details_frame.pack(side='left', fill='both', expand=True)

keybox_list_frame = ctk.CTkScrollableFrame(root,
                                            fg_color='#000000'
                                            )
keybox_list_frame.pack(side='right', fill='y')

certificate_frame = ctk.CTkScrollableFrame(keybox_details_frame,
                                            fg_color='#000000',
                                            width=400)

keybox_details_label = ctk.CTkLabel(keybox_details_frame,
                                    anchor='nw',
                                    justify='left',
                                    font=('Segoe UI', 20),
                                    corner_radius=6)

root.mainloop()