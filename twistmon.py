#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ssl
import glob
import shutil
import smtplib
import subprocess
from csv_diff import load_csv, compare
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Mail settings
mailto = "change@me.com"
mailfrom = "change@me.com"
mailpass = "pass"
smtp = "mail.server.com"
port = "465"

# Scan settings
temp = os.path.join(os.getcwd(), "temp")
scanpath = os.path.join(os.getcwd(), "scans")
dfile = os.path.join(os.getcwd(), "domains.txt")

args = './dnstwist.py --mxcheck --geoip --registered --ssdeep --threads 25 --tld dictionaries/common_tlds.dict --format csv'

def Mail(domain, new, data):
    # Send mail
    message = MIMEMultipart()
    message["From"] = mailfrom
    message["To"] = mailto
    if new == True:
        message["Subject"] = "dnstwist: Added new domain {}".format(domain)
        body = "The new domain {} has been added to your dnstwist monitoring, please review the attached file named {}".format(domain, os.path.basename(data))
        message.attach(MIMEText(body, "plain"))
        with open(data, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename= {os.path.basename(data)}",
        )
        message.attach(part)
        messagedata = message.as_string()

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp, port, context=context) as server:
            server.login(mailfrom, mailpass)
            server.sendmail(mailfrom, mailto, messagedata)

    else:
        # we're sending data
        message["Subject"] = "dnstwist: Changes detected for {}".format(domain)
        message.attach(MIMEText(data, "plain"))
        messagedata = message.as_string()
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp, port, context=context) as server:
            server.login(mailfrom, mailpass)
            server.sendmail(mailfrom, mailto, messagedata)


def Scan():
    # Run the new scans
    domains = open(dfile, 'r').readlines()
    for domain in domains:
        domain = domain.strip()
        output = os.path.join(temp, "{}.csv".format(domain))
        arguments = "{} {} >> {}".format(args, domain, output)
        data = subprocess.Popen([arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        data.communicate()

def ParseData(data):
    diff = data
    body = """"""
    if not diff['added'] == []:
        body += "\r\nADDED:"
        for a in diff['added']:
            for key, val in a.items():
                body += "\r\n\t" + key + ": \t" + val
            body += "\r\n"

    if not diff['removed'] == []:
        body += "\r\nREMOVED:"
        for r in diff['removed']:
            for key,val in r.items():
                body += "\r\n\t" + key + ": \t" + val
            body += "\r\n"
    
    if not diff['changed'] == []:
        body += "\r\nCHANGED:"
        for c in diff['changed']: # for key
            body += "\r\n\t" + c['key']
            for ch in c['changes']: # for changes
                body += "\r\n\t\t" + ch
                body += "\r\n\t\t\t" + c['changes'][ch][0] + " >> " + c['changes'][ch][1]
            body += "\r\n"
    return(body)

def Diff(email=True):
    for tfile in os.listdir(temp):
        if tfile.endswith(".csv"):
            tfile = os.path.join(temp, tfile)
            sfile = os.path.join(scanpath, os.path.basename(tfile))
            domain = os.path.basename(tfile).replace(".csv","")
            if os.path.exists(sfile):
                diff = compare(
                    load_csv(open(tfile), key="domain-name"),
                    load_csv(open(sfile), key="domain-name")
                )
                if not str(diff) == "{'added': [], 'removed': [], 'changed': [], 'columns_added': [], 'columns_removed': []}":
                    data = ParseData(diff)
                    if email:
                        Mail(domain=domain, new=False, data=data)
                    else:
                        print(data)
            else:
                # New domain, email the csv file
                Mail(domain, True, tfile)

def Update():
    # Update scan data
    for f in os.listdir(temp):
        try:
            shutil.move(os.path.join(temp, f), os.path.join(scanpath, f))
        except:
            print("{} is locked. Skipping.".format(f))

if __name__ == "__main__":
    if not os.path.exists(temp):
        os.mkdir(temp)
    if not os.path.exists(scanpath):
        os.mkdir(scanpath)
    if not os.path.exists(dfile):
        print("domains.txt missing!")
        exit(0)
    Scan()
    Diff(email=True)
    Update()
