"""
Collect open mail relays.
1. Accepts emails from any IP address and relays them to a specified destination.
"""

import argparse
import datetime
import hashlib
import json
import random
import re
import sys
import multiprocessing as mp
import smtplib
import email
import time
import uuid
from email.utils import formataddr, formatdate
import dkim
from tqdm import tqdm
import dns.resolver


def get_mx_records(domain):
    """Retrieve MX records and corresponding A records for a given domain."""
    mx_records = []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            mx_ips = get_ip_addresses(str(rdata.exchange))
            if len(mx_ips) != 0:
                for mx_ip in mx_ips:
                    mx_records.append({"mx": str(rdata.exchange), "ip": mx_ip})

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception:
        return []

    return mx_records


def extract_status_code(error_message):
    """Extract enhanced status code (X.X.X format) from an SMTP error message."""
    pattern = r'(\d{1}\.\d+\.\d+) '
    match = re.search(pattern, error_message)
    if match:
        return match.group(1)
    else:
        return "none"


def get_ip_addresses(hostname):
    """Resolve A records (IPv4 addresses) for the given hostname."""
    ip_addresses = []
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        for rdata in answers:
            ip_addresses.append(str(rdata))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception:
        return []

    return ip_addresses


def extract_reply_code(error_message):
    """Extract the 3-digit SMTP reply code from the error message."""
    pattern = r'^(\d{3})'
    match = re.match(pattern, error_message)
    if match:
        return match.group(1)
    else:
        return "none"


def generate_message_id(domain):
    """Generate a unique RFC 5322-compliant Message-ID."""
    unique_id = str(uuid.uuid4())
    timestamp = int(time.time())
    return f"<{unique_id}.{timestamp}@{domain}>"


def send_mail(target_domain, sender_domain, mail_exchange):
    """Attempt to send a test email via a target mail exchanger to detect open relay behavior."""
    dateid = formatdate(localtime=True)
    message_id = generate_message_id(sender_domain)

    current_time = datetime.datetime.now()
    current_datetime_str = current_time.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
    timestamp = str(current_datetime_str)

    sender_email = f"{timestamp}_check_{mail_exchange}@{sender_domain}"
    target_email = f"{timestamp}_check_{mail_exchange}@{target_domain}"

    message = (
        "From: {}\r\n"
        "To: {}\r\n"
        "Reply-To: {}\r\n"
        "Delivered-To: {}\r\n"
        "Return-Path: {}\r\n"
        "Subject: Email security test, please ignore\r\n"
        "Date: {}\r\n"
        "Message-ID: {}\r\n\r\n"
        "This is a harmless automated test message.\r\n"
        .format(sender_email, target_email, target_email, target_email, target_email, dateid, message_id)
    )

    try:
        server = smtplib.SMTP(str(mail_exchange), timeout=10)
        server.ehlo(sender_domain)

        server.sendmail(sender_email, [target_email], message)
        errcode, errmsg = server.quit()

        return errcode, errmsg, ""

    except (smtplib.SMTPSenderRefused, smtplib.SMTPConnectError, smtplib.SMTPAuthenticationError,
            smtplib.SMTPDataError, smtplib.SMTPResponseException, smtplib.SMTPHeloError) as e:
        return str(e.smtp_code), str(e.smtp_error), "except"

    except smtplib.SMTPRecipientsRefused as e:
        if len(list(e.recipients.values())) > 0:
            error = list(e.recipients.values())[0]
            return str(error[0]), str(error[1]), "except"
        else:
            return str(extract_reply_code(str(e))), str(e), "except"

    except Exception as e:
        return str(extract_reply_code(str(e))), str(e), "except"


def tigger(target_raw):
    """Test a single target IP for open relay behavior."""
    target_ip = target_raw.split(",")[0]
    target_domain = target_raw.split(",")[1]
    sender_domain = target_raw.split(",")[2]

    check_out_dict = {"target_ip": target_ip, "errcode": "", "errmsg": "", "flag": ""}

    check_out_dict["errcode"], check_out_dict["errmsg"], check_out_dict["flag"] = send_mail(
        target_domain, sender_domain, target_ip
    )

    return check_out_dict


def main(args):
    parser = argparse.ArgumentParser(description="Find open SMTP relays")
    parser.add_argument('input', help="Input file containing a list of target IPs or MX hosts")
    parser.add_argument('output', help="Output file to store results")
    parser.add_argument('-n', '--num-threads', help="Number of concurrent worker threads", default=64, type=int)
    parser.add_argument('-d', '--target-domain', help="Domain used as the recipient", default="", type=str)
    parser.add_argument('-s', '--sender-domain', help="Domain used as the sender", default="", type=str)
    parser.add_argument('-p', '--position_bar',
                        help="Position of tqdm progress bar (useful when running multiple instances)",
                        type=int, default=0)

    args = parser.parse_args(args)

    # Read input file
    in_file = open(args.input, "r")
    targets = in_file.readlines()
    in_file.close()

    target_list = []
    target_domain = args.target_domain
    sender_domain = args.sender_domain

    for target in targets:
        target = target.rstrip("\n")
        target_list.append(f"{target},{target_domain},{sender_domain}")

    threads = min(args.num_threads, len(target_list))

    # Run tests in parallel
    with open(args.output, 'a') as out_file:
        with mp.Pool(processes=threads) as p:
            try:
                for result in tqdm(
                        p.imap_unordered(tigger, target_list),
                        total=len(target_list),
                        desc="{} ({} threads)".format("tigger", threads),
                        position=args.position_bar):

                    try:
                        out_file.write(json.dumps(result))
                        out_file.write("\n")
                    except Exception as e:
                        print(e)
                        continue

            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Exiting early from queries. Current results will still be written.")


if __name__ == "__main__":
    main(sys.argv[1:])
