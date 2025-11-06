"""
Filter bounce servers that meet specific conditions:
1. Do not verify SPF
2. Respond to bounce messages consistently
3. Have short and fixed bounce time intervals
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
from email.utils import formataddr
import dkim
from tqdm import tqdm
import dns.resolver


def get_mx_records(domain):
    mx_records = []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            mx_ips = get_ip_addresses(str(rdata.exchange))
            if len(mx_ips) != 0:
                for mx_ip in mx_ips:
                    mx_records.append({"mx": str(rdata.exchange), "ip": mx_ip})
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except Exception as e:
        return []
    return mx_records


def extract_status_code(error_message):
    pattern = r'(\d{1}\.\d+\.\d+) '
    match = re.search(pattern, error_message)
    if match:
        return match.group(1)
    else:
        return "none"


def get_ip_addresses(hostname):
    ip_addresses = []
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        for rdata in answers:
            ip_addresses.append(str(rdata))
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except Exception as e:
        return []
    return ip_addresses


def extract_reply_code(error_message):
    pattern = r'^(\d{3})'
    match = re.match(pattern, error_message)
    if match:
        return match.group(1)
    else:
        return "none"


def check_err(errcode, errmsg, flag):
    check_end_time = datetime.datetime.now()
    check_end_time_str = check_end_time.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]

    response_result = str(errmsg)
    response_result = response_result.replace("\n", "")
    status_code = str(extract_status_code(response_result))
    return str(errcode), str(status_code), str(errmsg), flag, check_end_time_str


def generate_message_id(domain):
    unique_id = str(uuid.uuid4())
    timestamp = int(time.time())
    return f"<{unique_id}.{timestamp}@{domain}>"


def send_mail(send_domain, target_domain, mail_exchange):
    try:
        server = smtplib.SMTP(str(mail_exchange), timeout=20)

        # Send EHLO command
        server.ehlo(send_domain)

        # Send MAIL FROM command
        check_start_date = datetime.datetime.now()
        check_start_date_str = check_start_date.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
        send_email = target_domain + "_mutlicheck_" + check_start_date_str + "@" + send_domain
        server.mail(send_email)

        # Send RCPT TO command
        for loop_index in range(10, 15):
            check_start_date = datetime.datetime.now()
            check_start_date_str = check_start_date.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
            to_email = (
                target_domain
                + "_mutlicheck_"
                + str(loop_index)
                + "_"
                + check_start_date_str
                + "@"
                + target_domain
            )
            server.rcpt(to_email)

        message_id = generate_message_id(send_domain)
        message = (
            "From: {}\r\n"
            "To: {}\r\n"
            "Subject: Email security test, please ignore\r\n"
            "Message-ID: {}\r\n\r\n"
            "This is a harmless automated test message\r\n".format(
                send_email, target_domain + "_mutlifrom@" + target_domain, message_id
            )
        )

        # Send DATA command
        server.data(message)

        # Send QUIT command
        server.quit()

        check_end_time = datetime.datetime.now()
        check_end_time_str = check_end_time.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]

        return "success", "success", "success", "normal", check_end_time_str

    except (
        smtplib.SMTPSenderRefused,
        smtplib.SMTPConnectError,
        smtplib.SMTPAuthenticationError,
        smtplib.SMTPDataError,
        smtplib.SMTPResponseException,
        smtplib.SMTPHeloError,
    ) as e:
        return check_err(str(e.smtp_code), str(e.smtp_error), "except")

    except smtplib.SMTPRecipientsRefused as e:
        if len(list(e.recipients.values())) > 0:
            error = list(e.recipients.values())[0]
            return check_err(str(error[0]), str(error[1]), "except")
        else:
            return check_err(str(extract_reply_code(str(e))), str(e), "except")

    except Exception as e:
        return check_err(str(extract_reply_code(str(e))), str(e), "except")


def tigger(target_raw):
    target_domain = target_raw.split(",")[0]
    send_domain = target_raw.split(",")[1]

    MX_result_list = get_mx_records(target_domain)
    check_out_dict = {"target_domain": target_domain, "send_list": []}

    if len(MX_result_list) == 0:
        check_out_dict["start_time"] = "0-0-0-0-0-0"
        check_out_dict["end_time"] = "0-0-0-0-0-0"
        return check_out_dict

    random_integer = random.randint(5, 10)

    for loop_index in range(1111, 1112):
        random_mx = random.choice(MX_result_list)["ip"]
        response_code, status_code, response_result, flag, end_time = send_mail(
            send_domain, target_domain, random_mx
        )
        check_out_dict["send_list"].append(
            [send_domain, target_domain, random_mx, flag, end_time]
        )
        time.sleep(random_integer)

    return check_out_dict


def main(args):
    parser = argparse.ArgumentParser(description="Check SMTP timeout")
    parser.add_argument("input", help="Input file containing a list of ESPs")
    parser.add_argument("output", help="Output file to write results to")
    parser.add_argument(
        "-n", "--num-threads", help="Number of threads to execute queries", default=64, type=int
    )
    parser.add_argument(
        "-d", "--target-domain", help="Target domain name", default="", type=str
    )
    parser.add_argument(
        "-p",
        "--position_bar",
        help="The position of the tqdm progress bar. Used when running multiple bars in parallel",
        type=int,
        default=0,
    )

    args = parser.parse_args(args)

    # Read input file
    in_file = open(args.input, "r")
    targets = in_file.readlines()
    in_file.close()

    target_list = []
    send_domain = args.target_domain
    for target in targets:
        target = target.rstrip("\n")
        target_list.append(target + "," + send_domain)

    threads = min(args.num_threads, len(target_list))

    with open(args.output, "a") as out_file:
        with mp.Pool(processes=threads) as p:
            try:
                for result in tqdm(
                    p.imap_unordered(tigger, target_list),
                    total=len(target_list),
                    desc="{} ({} threads)".format("tigger_trap", threads),
                    position=args.position_bar,
                ):
                    out_file.write(json.dumps(result))
                    out_file.write("\n")
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print(
                    "Exiting early from queries. Current results will still be written."
                )


if __name__ == "__main__":
    main(sys.argv[1:])
