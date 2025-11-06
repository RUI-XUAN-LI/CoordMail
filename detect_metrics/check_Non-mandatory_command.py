"""
This script tests the support and response behavior of SMTP servers for various command types.
It is designed for controlled measurement experiments only, not for sending real emails.

Command categories:
- Mandatory_command: Basic commands defined in SMTP (RFC 5321)
- Optional_command: Additional or extended SMTP commands
- Outdated_command: Deprecated or obsolete commands
- Private_command: Vendor-specific or experimental commands
- Invalid_command: Non-standard or intentionally invalid commands
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


def generate_message_id(domain):
    """Generate a unique message ID using UUID and timestamp."""
    unique_id = str(uuid.uuid4())
    timestamp = int(time.time())
    return f"<{unique_id}.{timestamp}@{domain}>"


def get_mx_records(domain):
    """Query MX records for a given domain and return their IP addresses."""
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


def get_ip_addresses(hostname):
    """Resolve a hostname to its A record IP addresses."""
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


def is_valid_ip(address):
    """Check if the given string is a valid IPv4 address."""
    pattern = r'(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(pattern, address))


def extract_status_code(error_message):
    """Extract the enhanced status code (X.X.X) from SMTP response."""
    pattern = r'(\d{1}\.\d+\.\d+) '
    match = re.search(pattern, error_message)
    return match.group(1) if match else "none"


def extract_reply_code(error_message):
    """Extract the standard 3-digit reply code from SMTP response."""
    pattern = r'^(\d{3})'
    match = re.match(pattern, error_message)
    return match.group(1) if match else "none"


def change_timeout(timeout_dict, key, value):
    """Utility function for updating timeout settings."""
    timeout_dict[key] = value
    return timeout_dict


def check_err(errcode, errmsg, start_time, flag):
    """Measure response time and format SMTP error output."""
    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000
    response_result = str(errmsg).replace("\n", "")
    status_code = str(extract_status_code(response_result))
    return str(errcode), str(status_code), str(errmsg), duration_ms, flag


def check_max_timeout(send_domain, target_domain, mail_exchange, check_command, out_log_f):
    """Test server response to long timeout intervals for a given command."""
    current_time = datetime.datetime.now()
    timestamp = current_time.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
    result = hashlib.sha1(target_domain.encode()).hexdigest()
    MAIL_FROM_EMAIL = f"{timestamp}_{result[:5]}@{send_domain}"
    RCPT_TO_EMAIL = f"{timestamp}_{result[:5]}@{target_domain}"

    if check_command in ["VRFY", "EXPN", "ATRN", "SOML"]:
        args = RCPT_TO_EMAIL
    elif check_command == "BDAT":
        args = 1000
    elif check_command == "RELAY":
        args = target_domain
    else:
        args = ""

    timeout_list = [1, 58, 298]
    start_index = -1

    try:
        while True:
            smtp = smtplib.SMTP(str(mail_exchange), timeout=20)
            smtp.ehlo(send_domain)
            start_index += 1
            if start_index > 2:
                return 300

            start_timeout = timeout_list[start_index]

            if args == "none":
                smtp.putcmd(check_command)
            else:
                smtp.putcmd(check_command, args)

            time.sleep(start_timeout)
            errcode, errmsg = smtp.mail(MAIL_FROM_EMAIL)

            out_dict = {
                "from": send_domain,
                "to": target_domain,
                "target_mx": mail_exchange,
                "flag": "normal",
                "response_code": str(errcode),
                "response_result": str(errmsg),
                "check_command": check_command,
                "timeout": start_timeout,
            }
            out_log_f.write(json.dumps(out_dict) + "\n")
            smtp.putcmd("quit")

    except (
        smtplib.SMTPSenderRefused,
        smtplib.SMTPConnectError,
        smtplib.SMTPAuthenticationError,
        smtplib.SMTPDataError,
        smtplib.SMTPResponseException,
        smtplib.SMTPHeloError,
    ) as e:
        response_code = str(e.smtp_code)
        response_result = str(e.smtp_error).replace("\n", "")
        out_dict = {
            "from": send_domain,
            "to": target_domain,
            "target_mx": mail_exchange,
            "flag": "except",
            "response_code": response_code,
            "response_result": response_result,
            "check_command": check_command,
            "timeout": timeout_list[start_index],
        }
        out_log_f.write(json.dumps(out_dict) + "\n")
        return timeout_list[start_index]

    except smtplib.SMTPRecipientsRefused as e:
        if len(list(e.recipients.values())) > 0:
            error = list(e.recipients.values())[0]
            response_code = str(error[0])
            response_result = str(error[1]).replace("\n", "")
        else:
            response_code = str(extract_reply_code(str(e)))
            response_result = str(e).replace("\n", "")

        out_dict = {
            "from": send_domain,
            "to": target_domain,
            "target_mx": mail_exchange,
            "flag": "except",
            "response_code": response_code,
            "response_result": response_result,
            "check_command": check_command,
            "timeout": timeout_list[start_index],
        }
        out_log_f.write(json.dumps(out_dict) + "\n")
        return timeout_list[start_index]

    except Exception as e:
        response_code = str(extract_reply_code(str(e)))
        response_result = str(e).replace("\n", "")
        out_dict = {
            "from": send_domain,
            "to": target_domain,
            "target_mx": mail_exchange,
            "flag": "except",
            "response_code": response_code,
            "response_result": response_result,
            "check_command": check_command,
            "timeout": timeout_list[start_index],
        }
        out_log_f.write(json.dumps(out_dict) + "\n")
        return timeout_list[start_index]


def check_max_num(send_domain, target_domain, mail_exchange, check_command, out_log_f):
    """Test how many times the server accepts a given command in a loop."""
    current_time = datetime.datetime.now()
    timestamp = current_time.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
    result = hashlib.sha1(target_domain.encode()).hexdigest()
    MAIL_FROM_EMAIL = f"{timestamp}_{result[:5]}@{send_domain}"
    RCPT_TO_EMAIL = f"{timestamp}_{result[:5]}@{target_domain}"

    if check_command in ["VRFY", "EXPN", "ATRN", "SOML"]:
        args = RCPT_TO_EMAIL
    elif check_command == "BDAT":
        args = 1000
    elif check_command == "RELAY":
        args = target_domain
    else:
        args = ""

    loop_num = 0
    try:
        smtp = smtplib.SMTP(str(mail_exchange), timeout=20)
        errcode, errmsg = smtp.ehlo(send_domain)
        while True:
            loop_num += 1
            if loop_num > 30:
                smtp.putcmd("quit")
                return loop_num

            if args == "none":
                smtp.putcmd(check_command)
            else:
                smtp.putcmd(check_command, args)

            errcode, errmsg = smtp.getreply()

            out_dict = {
                "from": send_domain,
                "to": target_domain,
                "target_mx": mail_exchange,
                "flag": "normal",
                "response_code": str(errcode),
                "response_result": str(errmsg),
                "check_command": check_command,
                "loop_num": loop_num,
            }
            out_log_f.write(json.dumps(out_dict) + "\n")
            time.sleep(1)

    except Exception as e:
        response_code = getattr(e, "smtp_code", extract_reply_code(str(e)))
        response_result = str(getattr(e, "smtp_error", e)).replace("\n", "")
        out_dict = {
            "from": send_domain,
            "to": target_domain,
            "target_mx": mail_exchange,
            "flag": "except",
            "response_code": str(response_code),
            "response_result": response_result,
            "check_command": check_command,
            "loop_num": loop_num,
        }
        out_log_f.write(json.dumps(out_dict) + "\n")
        return loop_num


def tigger(target_raw):
    """Main worker function to test a given MX and command."""
    target_mxip = target_raw.split(",")[0]
    send_domain = target_raw.split(",")[1]
    log_file = target_raw.split(",")[2]
    send_type = target_raw.split(",")[3]
    target_domain_list = target_raw.split(",")[4].split(";")

    target_domain = ""
    for domain in target_domain_list:
        MX_result_list = get_mx_records(domain)
        mxip_list = [item["ip"] for item in MX_result_list]
        if target_mxip in mxip_list:
            target_domain = domain
            break

    if target_domain == "":
        target_domain = random.choice(target_domain_list)
        MX_result_list = get_mx_records(target_domain)
        if len(MX_result_list) != 0:
            target_mxip = random.choice(MX_result_list)["ip"]

    out_log_f = open(log_file, "a")
    random_integer = random.randint(5, 10)
    if target_domain == "":
        return "err"

    check_start_date = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
    random_mx = target_mxip
    check_out_dict = {
        "from": send_domain,
        "to": target_domain,
        "mx": random_mx,
        "start_time": check_start_date,
        "check_command": send_type,
        "max_num": "",
        "max_timeout": "",
    }

    check_out_dict["max_num"] = check_max_num(send_domain, target_domain, random_mx, send_type, out_log_f)
    time.sleep(random_integer)
    check_out_dict["max_timeout"] = check_max_timeout(send_domain, target_domain, random_mx, send_type, out_log_f)

    check_out_dict["end_time"] = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
    return check_out_dict


def main(args):
    parser = argparse.ArgumentParser(description="SMTP command behavior test script")
    parser.add_argument("input", help="Input JSON file containing target ESP domains")
    parser.add_argument("output", help="Output file to write summarized results")
    parser.add_argument("-n", "--num-threads", help="Number of concurrent worker threads", default=64, type=int)
    parser.add_argument("-l", "--log-file", help="Log file for detailed results", default="", type=str)
    parser.add_argument("-d", "--send-domain", help="Sender domain used in EHLO and MAIL FROM", default="", type=str)
    parser.add_argument("-p", "--position_bar", help="Progress bar position for tqdm", type=int, default=0)

    args = parser.parse_args(args)
    with open(args.input, "r") as in_file:
        data = json.load(in_file)

    send_domain = args.send_domain

    Optional_command = ["VRFY", "HELP", "NOOP"]
    Outdated_command = ["TURN"]
    Private_command = ["XADR"]
    Invalid_command = ["abcd"]

    check_command_list = []
    for command in Optional_command + Outdated_command + Private_command + Invalid_command:
        if command in ["VRFY", "EXPN", "ATRN"]:
            check_command_list.append(f"{command}={send_domain}")
        elif command == "BDAT":
            check_command_list.append(f"{command}=1000")
        else:
            check_command_list.append(command)

    target_list = []
    for index, value in data.items():
        for command in check_command_list:
            target_list.append(
                f"{index},{send_domain},{args.log_file},{command},{';'.join(value)}"
            )

    threads = min(args.num_threads, len(target_list))

    with open(args.output, "a") as out_file:
        with mp.Pool(processes=threads) as p:
            try:
                for result in tqdm(
                    p.imap_unordered(tigger, target_list),
                    total=len(target_list),
                    desc=f"tigger_trap ({threads} threads)",
                    position=args.position_bar,
                ):
                    if result != "err":
                        out_file.write(json.dumps(result) + "\n")
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Interrupted by user, exiting early.")


if __name__ == "__main__":
    main(sys.argv[1:])
