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
    """Resolve MX records for a given domain."""
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
    except Exception:
        return []
    return mx_records


def get_ip_addresses(hostname):
    """Resolve A records for a given hostname."""
    ip_addresses = []
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        for rdata in answers:
            ip_addresses.append(str(rdata))
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return []
    except Exception:
        return []
    return ip_addresses


def is_valid_ip(address):
    """Check if a string is a valid IPv4 address."""
    pattern = r'(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(pattern, address))


def extract_status_code(error_message):
    """Extract the extended status code (x.x.x) from SMTP error message."""
    pattern = r'(\d{1}\.\d+\.\d+) '
    match = re.search(pattern, error_message)
    if match:
        return match.group(1)
    else:
        return "none"


def extract_reply_code(error_message):
    """Extract the 3-digit SMTP reply code from error message."""
    pattern = r'^(\d{3})'
    match = re.match(pattern, error_message)
    if match:
        return match.group(1)
    else:
        return "none"


def change_timeout(timeout_dict, key, value):
    """Update a timeout value in the timeout dictionary."""
    timeout_dict[key] = value
    return timeout_dict


def check_err(errcode, errmsg, start_time, flag):
    """Return error information and elapsed time."""
    end_time = time.perf_counter()
    duration_ms = (end_time - start_time) * 1000
    response_result = str(errmsg).replace("\n", "")
    status_code = str(extract_status_code(response_result))
    return str(errcode), str(status_code), str(errmsg), duration_ms, flag


def send_mail(send_domain, target_domain, mail_exchange, timeout_second_dict):
    """Perform an SMTP session with controlled delays to measure timeout tolerance."""
    start_time = time.perf_counter()
    current_time = datetime.datetime.now()
    timestamp = current_time.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
    result = hashlib.sha1(target_domain.encode()).hexdigest()

    MAIL_FROM_EMAIL = timestamp + "_" + result[:5] + "@" + send_domain
    RCPT_TO_EMAIL = timestamp + "_" + result[:5] + "@" + target_domain
    EMAIL_CONTENT = ["line1"]

    try:
        smtp = smtplib.SMTP(str(mail_exchange), timeout=20)
        time.sleep(timeout_second_dict['tcp'])

        errcode, errmsg = smtp.ehlo(MAIL_FROM_EMAIL.split("@")[-1])
        if timeout_second_dict['tcp'] > 0:
            smtp.putcmd("quit")
            return check_err(errcode, errmsg, start_time, "normal")

        time.sleep(timeout_second_dict['helo'])
        errcode, errmsg = smtp.mail(MAIL_FROM_EMAIL)
        if timeout_second_dict['helo'] > 0:
            smtp.putcmd("quit")
            return check_err(errcode, errmsg, start_time, "normal")

        time.sleep(timeout_second_dict['mail_from'])
        errcode, errmsg = smtp.rcpt(RCPT_TO_EMAIL)
        if timeout_second_dict['mail_from'] > 0:
            smtp.putcmd("quit")
            return check_err(errcode, errmsg, start_time, "normal")

        time.sleep(timeout_second_dict['rcpt_to'])
        smtp.send("DATA\r\n")
        errcode, errmsg = smtp.getreply()
        if timeout_second_dict['rcpt_to'] > 0:
            smtp.putcmd("quit")
            return check_err(errcode, errmsg, start_time, "normal")

        time.sleep(timeout_second_dict['data'])
        smtp.send("From: {}\r\n".format(MAIL_FROM_EMAIL))
        time.sleep(timeout_second_dict['from'])
        smtp.send("To: {}\r\n".format(RCPT_TO_EMAIL))
        time.sleep(timeout_second_dict['to'])
        smtp.send("Subject: {}\r\n".format("TEST"))

        message_id = generate_message_id(MAIL_FROM_EMAIL.split("@")[-1])
        smtp.send(f"Message-ID: {message_id}\r\n\r\n")

        for line in EMAIL_CONTENT:
            smtp.send(line + "\r\n")
            time.sleep(timeout_second_dict['content'])

        smtp.send("\r\n.\r\n")
        errcode, errmsg = smtp.getreply()
        if timeout_second_dict['data'] > 0 or timeout_second_dict['from'] > 0 or timeout_second_dict['to'] > 0 or \
                timeout_second_dict['content'] > 0:
            smtp.putcmd("quit")
            return check_err(errcode, errmsg, start_time, "normal")

        time.sleep(timeout_second_dict['end'])
        errcode, errmsg = smtp.quit()
        if timeout_second_dict['end'] > 0:
            return check_err(errcode, errmsg, start_time, "normal")

        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        return "success", "success", "success", duration_ms, "normal"

    except (smtplib.SMTPSenderRefused, smtplib.SMTPConnectError, smtplib.SMTPAuthenticationError,
            smtplib.SMTPDataError, smtplib.SMTPResponseException, smtplib.SMTPHeloError) as e:
        return check_err(str(e.smtp_code), str(e.smtp_error), start_time, "except")

    except smtplib.SMTPRecipientsRefused as e:
        if len(list(e.recipients.values())) > 0:
            error = list(e.recipients.values())[0]
            return check_err(str(error[0]), str(error[1]), start_time, "except")
        else:
            return check_err(str(extract_reply_code(str(e))), str(e), start_time, "except")

    except Exception as e:
        return check_err(str(extract_reply_code(str(e))), str(e), start_time, "except")


def tigger(target_raw):
    """Run timeout probing for a specific MX IP and domain group."""
    target_mxip = target_raw.split(",")[0]
    send_domain = target_raw.split(",")[1]
    log_file = target_raw.split(",")[2]
    send_type = target_raw.split(",")[3]
    target_domain_list = target_raw.split(",")[4].split(";")

    target_domain = ""
    for domain in target_domain_list:
        MX_result_list = get_mx_records(domain)
        mxip_list = [item['ip'] for item in MX_result_list]
        if target_mxip in mxip_list:
            target_domain = domain
            break

    if target_domain == "":
        target_domain = random.choice(target_domain_list)
        MX_result_list = get_mx_records(target_domain)
        if len(MX_result_list) != 0:
            target_mxip = random.choice(MX_result_list)['ip']

    check_start_date = datetime.datetime.now()
    check_start_date_str = check_start_date.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
    out_log_f = open(log_file, "a")

    timeout_second_dict = {"tcp": 0, "helo": 0, "mail_from": 0, "rcpt_to": 0, "data": 0, "from": 0, "to": 0,
                           "content": 0, "end": 0}
    max_timeout_second_dict = timeout_second_dict.copy()
    timeout_key_list = list(timeout_second_dict.keys())
    random_integer = random.randint(10, 20)
    timeout_list = [1, 4, 9, 28, 58, 118, 178, 298]

    if target_domain == "":
        check_end_date = datetime.datetime.now()
        checkend_date_str = check_end_date.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
        max_timeout_second_dict['tcp'] = -1
        return {"from": send_domain, "to": target_domain, "start_time": check_start_date_str,
                "end_time": checkend_date_str, "max_timeout": max_timeout_second_dict}

    if send_type != "all" and send_type in timeout_second_dict.keys():
        for start_timeout in timeout_list:
            timeout_second_dict = change_timeout(timeout_second_dict, send_type, start_timeout)
            random_mx = target_mxip
            current_time = datetime.datetime.now()
            current_datetime_str = current_time.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]

            out_dict = {"from": send_domain, "to": target_domain, "target_mx_ip": random_mx, "flag": "",
                        "response_code": "", "status_code": "", "response_result": "",
                        "time": current_datetime_str, "duration_ms": 0, "timeout_second_dict": timeout_second_dict}

            out_dict["response_code"], out_dict["status_code"], out_dict["response_result"], \
            out_dict["duration_ms"], out_dict["flag"] = send_mail(send_domain, target_domain,
                                                                  out_dict["target_mx_ip"], timeout_second_dict)

            out_log_f.write(json.dumps(out_dict) + "\n")

            if out_dict["flag"] == "except":
                max_timeout_second_dict[send_type] = start_timeout
                timeout_second_dict = change_timeout(timeout_second_dict, send_type, 0)
                break

            if start_timeout == 298:
                max_timeout_second_dict[send_type] = 300
                timeout_second_dict = change_timeout(timeout_second_dict, send_type, 0)
                break

            time.sleep(random_integer)

    elif send_type == "all":
        for key in timeout_key_list:
            for start_timeout in timeout_list:
                timeout_second_dict = change_timeout(timeout_second_dict, key, start_timeout)
                random_mx = target_mxip
                current_time = datetime.datetime.now()
                current_datetime_str = current_time.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]

                out_dict = {"from": send_domain, "to": target_domain, "target_mx_ip": random_mx, "flag": "",
                            "response_code": "", "status_code": "", "response_result": "",
                            "time": current_datetime_str, "duration_ms": 0,
                            "timeout_second_dict": timeout_second_dict}

                out_dict["response_code"], out_dict["status_code"], out_dict["response_result"], \
                out_dict["duration_ms"], out_dict["flag"] = send_mail(send_domain, target_domain,
                                                                      out_dict["target_mx_ip"], timeout_second_dict)

                out_log_f.write(json.dumps(out_dict) + "\n")

                if out_dict["flag"] == "except" or "timed" in out_dict["response_result"] or "timeout" in out_dict["response_result"]:
                    max_timeout_second_dict[key] = start_timeout
                    timeout_second_dict = change_timeout(timeout_second_dict, key, 0)
                    break

                if start_timeout == 298:
                    max_timeout_second_dict[key] = 300
                    timeout_second_dict = change_timeout(timeout_second_dict, key, 0)
                    break

                time.sleep(random_integer)

    check_end_date = datetime.datetime.now()
    checkend_date_str = check_end_date.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
    return {"from": send_domain, "to": target_domain, "mxip": target_mxip,
            "start_time": check_start_date_str, "end_time": checkend_date_str,
            "max_timeout": max_timeout_second_dict}


def main(args):
    parser = argparse.ArgumentParser(description="SMTP Timeout Measurement Tool")
    parser.add_argument('input', help="Input file containing MX-domain mappings in JSON format")
    parser.add_argument('output', help="Output file to write aggregated results")
    parser.add_argument('-n', '--num-threads', help="Number of parallel threads", default=64, type=int)
    parser.add_argument('-l', '--log-file', help="Per-session log file path", default="", type=str)
    parser.add_argument('-d', '--target-domain', help="Sender domain name", default="", type=str)
    parser.add_argument('-t', '--send-type', help="Specific SMTP phase to test or 'all'", default="", type=str)
    parser.add_argument('-p', '--position_bar', help="Position index for tqdm progress bar", type=int, default=0)
    args = parser.parse_args(args)

    target_list = []
    with open(args.input, "r") as in_file:
        data = json.load(in_file)
        for index, value in data.items():
            target_list.append(index + "," + args.target_domain + "," + str(args.log_file) + "," +
                               args.send_type + "," + ';'.join(value))

    threads = min(args.num_threads, len(target_list))

    with open(args.output, 'a') as out_file:
        with mp.Pool(processes=threads) as p:
            try:
                for result in tqdm(p.imap_unordered(tigger, target_list), total=len(target_list),
                                   desc=f"SMTP Timeout Probe ({threads} threads)", position=args.position_bar):
                    print(result)
                    out_file.write(json.dumps(result) + "\n")
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Interrupted manually. Partial results have been saved.")


if __name__ == "__main__":
    main(sys.argv[1:])
