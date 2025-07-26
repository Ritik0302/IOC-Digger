
import re
import ipaddress
import email
from email import policy
import hashlib

start = '\033[91m'
end = '\033[0m'


def valid_ip(value):
    l1=[]
    for i in value:
        try:
            ip = ipaddress.ip_address(i)
            if ip not in l1:
                print(ip)
                l1.append(ip)
        except Exception as e:
            continue
    l1.clear()
    return

def printing(value):
    l1=[]
    for i in value:
        if i not in l1:
            print(i)
            l1.append(i)
    l1.clear()
    return

fname=input("Enter the filename with accurate  path : ")
with open(fname, 'r') as file:
    content = file.read()

ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'
urlptrn = r'https?://[^\s"<>()]+'
decoded_html = content.replace('=3D', '=').replace('=\n', '').replace('=\r\n', '')


# Building pattern to get matched

ipv4 = re.findall(ipv4_pattern, content)
ipv6 = re.findall(ipv6_pattern, content)
url1 = re.findall(urlptrn, decoded_html)

#  It converts the raw .eml text into an EmailMessage object from Python’s built-in email package, allowing you to easily access headers like msg['Subject'] and msg['From'], inspect attachments and different body parts or MIME types, and automatically handle decoding of the email content.

msg = email.message_from_string(content, policy=policy.default) 

# Headers we want to extract

wanted_headers = [
    "Return-Path",
    "Authentication-Results",
    "From",
    "Date",
    "Message-ID",
    "Subject",
    "To",
    "Reply-To",
    "X-Sender-IP"
]

print(start,"\n=============== IPV4 ADDRESSES ===============\n",end)
valid_ip(ipv4)
print(start,"=============== IPV6 ADDRESSES ===============\n",end)
valid_ip(ipv6)
print(start,"=============== URL EXTRACTED ===============\n",end)
printing(url1)
print(start,"=============== EXTRACTED HEADERS ===============\n",end)

for header in wanted_headers:
    value = msg.get(header)
    if value:
        print(f"{header}: {value}")

# Checking for attachments

print(start,"=============== ATTACHMENT FOUND ===============\n",end)

for part in msg.iter_parts():
    if part.get_content_disposition() == 'attachment':
        filename = part.get_filename()
        payload = part.get_payload(decode=True)  
        md5 = hashlib.md5(payload).hexdigest()
        sha1 = hashlib.sha1(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()

        print(f"Attachment: {filename}")
        print(f"  MD5:     {md5}")
        print(f"  SHA-1:   {sha1}")
        print(f"  SHA-256: {sha256}")
