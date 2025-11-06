#!/usr/bin/env python3
"""
Offline SMTP "bounce pulse" simulator for academic publication (SAFE)

This script is a fully offline simulator derived from an experimental script.
It DOES NOT perform any real network connections or send any email. Instead,
it simulates SMTP interactions, timing, and server behaviors so researchers
can reproduce timing-dependent experiments without creating real-world harm.

USAGE (example):
    python offline_bounce_simulator.py config.json output.log \
        --attack-rate 0.5 --server-num 10 --victim-email victim@example.com \
        --attack-time "2025-11-10-12-00-00-000" --loop-num 5

Ethics / Safety:
- This simulator is intended for controlled, ethical research only.
- Do NOT adapt it to interact with real SMTP servers or real recipients.
- Replace test identifiers with anonymized placeholders when publishing.
"""

from __future__ import annotations
import argparse
import datetime
import json
import multiprocessing
import random
import re
import string
import sys
import time
import uuid
from typing import Dict, List, Tuple

from tqdm import tqdm

# ---------------------------------------------------------------------
# Configuration: command lists and defaults
# ---------------------------------------------------------------------
MANDATORY_COMMANDS = ["EHLO", "HELO", "MAIL", "RCPT", "DATA", "QUIT"]

# ---------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------
def generate_message_id(domain: str) -> str:
    """Generate a unique Message-ID (purely synthetic)."""
    unique_id = uuid.uuid4().hex
    timestamp = int(time.time() * 1000)
    return f"<{unique_id}.{timestamp}@{domain}>"

def extract_numeric_status(text: str) -> str:
    """Try to extract an X.Y.Z style status code from text (simulation)."""
    match = re.search(r"(\d+\.\d+\.\d+)", text)
    return match.group(1) if match else "none"

def extract_reply_code(text: str) -> str:
    """Try to extract a three-digit reply code from a string."""
    match = re.match(r"^(\d{3})", text)
    return match.group(1) if match else "none"

def random_alnum(n: int) -> str:
    """Return a random alphanumeric string of length n."""
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))

# ---------------------------------------------------------------------
# Mock SMTP implementation: all interactions are simulated locally.
# ---------------------------------------------------------------------
class MockSMTP:
    """
    A safe, local-only mock of an SMTP connection.

    Methods mimic a subset of smtplib.SMTP interface used by the original code:
    - ehlo(domain)
    - mail(address)
    - rcpt(address)
    - putcmd(command, arg=None)
    - send(data)
    - getreply()
    - quit()

    This class does not open any sockets. It simulates reply codes and delays.
    """

    def __init__(self, server_name: str, behavior: Dict = None, timeout: int = 20):
        self.server_name = server_name
        self.behavior = behavior or {}
        self.timeout = timeout
        self._last_command = None
        self._closed = False
        # internal simulated counters
        self._command_count = 0

    def _simulate_reply(self, command: str) -> Tuple[int, str]:
        """Return a simulated (code, message) for a given command."""
        self._command_count += 1

        # base behavior - can be extended by behavior dict
        if command in ("EHLO", "HELO"):
            return 250, f"2.0.0 {command} accepted by {self.server_name}"
        if command == "MAIL":
            return 250, "2.1.0 Sender OK"
        if command == "RCPT":
            # randomly simulate accepted or recipient refused in a reproducible way
            if random.random() < 0.95:
                return 250, "2.1.5 Recipient OK"
            else:
                return 550, "5.1.1 Recipient refused"
        if command == "DATA":
            return 354, "3.0.0 Start mail input; end with <CRLF>.<CRLF>"
        if command == "QUIT":
            return 221, "2.0.0 Bye"
        # optional commands
        if command in ("VRFY", "NOOP", "RSET"):
            return 250, f"2.0.0 {command} processed"
        # fallback
        return 250, f"2.0.0 {command} OK"

    def ehlo(self, domain: str):
        self._last_command = "EHLO"
        code, msg = self._simulate_reply("EHLO")
        return code, msg

    def mail(self, sender: str):
        self._last_command = "MAIL"
        code, msg = self._simulate_reply("MAIL")
        return code, msg

    def rcpt(self, recipient: str):
        self._last_command = "RCPT"
        code, msg = self._simulate_reply("RCPT")
        return code, msg

    def putcmd(self, cmd: str, args: str = None):
        """Simulate sending a command; doesn't block."""
        self._last_command = cmd if args is None else f"{cmd} {args}"
        # small deterministic pause to mimic processing
        time.sleep(0.01)
        return

    def send(self, data: str):
        """Pretend to send raw data (no network I/O)."""
        # no-op; we keep track of last 'send'
        self._last_sent = data
        return

    def getreply(self) -> Tuple[int, str]:
        """Return a reply for the last command sent."""
        # Use last_command to determine reply; if none, return generic
        if self._last_command is None:
            return 250, "2.0.0 OK"
        # extract base command token
        token = self._last_command.split()[0]
        code, msg = self._simulate_reply(token)
        return code, msg

    def quit(self):
        self._closed = True
        return 221, "2.0.0 Closed"

# ---------------------------------------------------------------------
# Core simulation utilities (timing selection logic preserved)
# ---------------------------------------------------------------------
def evaluate_server_timing(server_profile: Dict, available_seconds: int) -> Tuple[bool, Dict[str, float], List[Tuple[str, float]]]:
    """
    Decide which mandatory and optional commands will be active given the
    time window available before the simulated 'attack end time'.

    Returns:
        - ok_flag: whether the server can be used
        - mandatory_selection: dict mapping mandatory commands to allocated seconds
        - optional_order: list of (optional_command, seconds) scheduled
    This keeps the original algorithmic spirit but operates purely on numbers.
    """
    # guardrails
    if available_seconds <= 0:
        return False, {}, []

    mandatory = server_profile.get("mandatory_command_dict", {})
    optional_num = server_profile.get("optional_command_num_dict", {})
    optional_time = server_profile.get("optional_command_time_dict", {})

    # compute ratio across mandatory commands (avoid divide-by-zero)
    mandatory_times = list(mandatory.values()) if mandatory else []
    mandatory_sum = sum(mandatory_times) if mandatory_times else 0.0
    # If mandatory_sum is zero, we reject this server
    if mandatory_sum <= 0:
        return False, {}, []

    mandatory_ratio = {cmd: (t / mandatory_sum) for cmd, t in mandatory.items()}

    mandatory_allocation: Dict[str, float] = {}
    optional_schedule: List[Tuple[str, float]] = []

    # reserve a small buffer similar to original logic
    effective_mandatory_sum = max(0.0, mandatory_sum - 30.0)

    if effective_mandatory_sum > available_seconds:
        # allocate portionally to the available time
        for cmd, ratio in mandatory_ratio.items():
            mandatory_allocation[cmd] = available_seconds * ratio
        return True, mandatory_allocation, optional_schedule
    else:
        for cmd, ratio in mandatory_ratio.items():
            mandatory_allocation[cmd] = effective_mandatory_sum * ratio

        remaining = available_seconds - effective_mandatory_sum
        if remaining <= 0:
            return False, mandatory_allocation, optional_schedule

        # pick optional commands until remaining time is used
        accumulated = 0.0
        # iterate optional candidates (skip RESET as original)
        for cmd, cnt in optional_num.items():
            if cmd.upper() == "RESET":
                continue
            if cnt < 4:
                continue
            cmd_time = optional_time.get(cmd, 0)
            if cmd_time < 30:
                continue
            # subtract internal buffer
            cmd_time_adj = max(0.0, cmd_time - 20.0)
            # add this command multiple times as allowed
            for _ in range(cnt - 3):
                if accumulated >= remaining:
                    break
                optional_schedule.append((cmd, cmd_time_adj))
                accumulated += cmd_time_adj
            if accumulated >= remaining:
                break

        ok_flag = len(optional_schedule) > 0 or remaining <= accumulated
        return ok_flag, mandatory_allocation, optional_schedule

# ---------------------------------------------------------------------
# Simulated end-of-session routine that composes a final synthetic reply
# ---------------------------------------------------------------------
def finalize_session(sim_smtp: MockSMTP, stage: str, mail_from: str, rcpt_to: str) -> Tuple[str, str, str, str, str]:
    """
    Simulate sending the final mail content and closing the session.
    Returns a 5-tuple mirroring the original script's log fields:
      (response_code, status_code, response_result, end_time_str, flag)
    """
    try:
        # Simulated sequence: send minimal headers and terminate DATA
        domain = (mail_from.split("@")[-1] if "@" in mail_from else "example.local")
        sim_smtp.send(f"From: {mail_from}\r\n")
        sim_smtp.send(f"To: {rcpt_to}\r\n")
        sim_smtp.send("Subject: SIMULATED_TEST\r\n")
        sim_smtp.send(f"Message-ID: {generate_message_id(domain)}\r\n\r\n")
        sim_smtp.send("SIMULATED BODY\r\n")
        sim_smtp.send("\r\n.\r\n")
        code, msg = sim_smtp.getreply()
        sim_smtp.quit()

        end_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
        return str(code), extract_numeric_status(msg), str(msg), end_time, "normal"
    except Exception as e:
        end_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
        return extract_reply_code(str(e)), "none", str(e), end_time, "except"

# ---------------------------------------------------------------------
# Worker: simulate sending one "attack" session against a bounce server
# ---------------------------------------------------------------------
def simulate_session(victim: str,
                     server_name: str,
                     server_profile: Dict,
                     output_log_path: str,
                     stop_event: multiprocessing.Event,
                     end_time: datetime.datetime,
                     rcpt_loop: int):
    """
    Simulate an entire staged SMTP session against a single synthetic bounce server.
    All I/O is local: writes a single JSON line to output_log_path on completion.
    """
    # Safety: if server has no domain_list, abort simulation
    domains = server_profile.get("domain_list", [])
    if not domains:
        print(f"[WARN] Server {server_name} has no domains configured; skipping.")
        return

    # open log file in append mode
    with open(output_log_path, "a", encoding="utf-8") as log_f:
        start_time = datetime.datetime.now()
        start_ts = start_time.strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]

        record = {
            "from": "",
            "to": "",
            "server": server_name,
            "flag": "",
            "wait_stage": "",
            "response_code": "",
            "status_code": "",
            "response_result": "",
            "time_bounce_process": server_profile.get("time_bounce_process", -1),
            "mandatory_time_allocation": {},
            "optional_schedule": [],
            "start_time": start_ts,
            "end_time": ""
        }

        # time budget until target end_time (in seconds)
        now = datetime.datetime.now()
        available_seconds = int((end_time - now).total_seconds())
        ok, mandatory_alloc, optional_sched = evaluate_server_timing(server_profile, available_seconds)
        if not ok:
            record["flag"] = "insufficient_time"
            record["response_result"] = "Server cannot be scheduled in the available time window"
            record["end_time"] = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
            log_f.write(json.dumps(record) + "\n")
            print(f"[INFO] Server {server_name} skipped due to insufficient time.")
            return

        record["mandatory_time_allocation"] = mandatory_alloc
        record["optional_schedule"] = optional_sched

        # pick a synthetic mail-from and one rcpt address template (purely local/test)
        test_domain = random.choice(domains)
        if "@" in victim:
            mail_from = victim  # keep victim address as the simulated MAIL FROM (paper may provide this)
            rcpt_to = f"{random_alnum(5)}_TEST_@{test_domain}"
            print(f"[SIM] Server {server_name}: from={mail_from}, to={rcpt_to}")
        else:
            # if victim is not an address, use a placeholder
            mail_from = f"sim-sender@{test_domain}"
            rcpt_to = f"{random_alnum(5)}_TEST_@{test_domain}"
            print(f"[SIM] Server {server_name}: using placeholder sender and recipient")

        record["from"] = mail_from
        record["to"] = rcpt_to

        # create a MockSMTP connection (no network)
        simulated_smtp = MockSMTP(server_name, behavior=server_profile.get("behavior", {}), timeout=20)

        try:
            # Simulate each mandatory stage in order: tcp (EHLO), helo, optional, mail_from, rcpt, data, headers, content
            # The original code used 'tcp' as the initial waiting stage; we map it to EHLO here.
            # For each stage: wait until either allocated time elapses or stop_event is set, then finalize.

            # --- EHLO / TCP stage ---
            sim_stop = time.time() + mandatory_alloc.get("tcp", 0)
            record["wait_stage"] = "tcp"
            while True:
                if stop_event.is_set():
                    record["response_code"], record["status_code"], record["response_result"], record["end_time"], record["flag"] = \
                        finalize_session(simulated_smtp, "tcp", mail_from, rcpt_to)
                    log_f.write(json.dumps(record) + "\n")
                    print(f"[+SIM] {server_name} completed (interrupted during tcp).")
                    return
                if time.time() > sim_stop:
                    break
                # simulate light local CPU work
                time.sleep(0.01)

            # EHLO exchange
            code, msg = simulated_smtp.ehlo(mail_from.split("@")[-1])
            # store last reply (synthetic)
            last_code, last_msg = code, msg

            # --- HELO stage ---
            sim_stop = time.time() + mandatory_alloc.get("helo", 0)
            record["wait_stage"] = "helo"
            while True:
                if stop_event.is_set():
                    record["response_code"], record["status_code"], record["response_result"], record["end_time"], record["flag"] = \
                        finalize_session(simulated_smtp, "helo", mail_from, rcpt_to)
                    log_f.write(json.dumps(record) + "\n")
                    print(f"[+SIM] {server_name} completed (interrupted during helo).")
                    return
                if time.time() > sim_stop:
                    break
                time.sleep(0.01)

            # --- Optional commands ---
            for opt_cmd, opt_time in optional_sched:
                # simulate issuing an optional command; some commands take an argument
                if opt_cmd.upper() == "VRFY":
                    simulated_smtp.putcmd("VRFY", rcpt_to)
                else:
                    simulated_smtp.putcmd(opt_cmd)
                # immediate reply
                code, msg = simulated_smtp.getreply()
                # wait for the allocated optional command time or until stop
                sim_stop = time.time() + opt_time
                record["wait_stage"] = f"optional;{opt_cmd}"
                while True:
                    if stop_event.is_set():
                        record["response_code"], record["status_code"], record["response_result"], record["end_time"], record["flag"] = \
                            finalize_session(simulated_smtp, "optional", mail_from, rcpt_to)
                        log_f.write(json.dumps(record) + "\n")
                        print(f"[+SIM] {server_name} completed (interrupted during optional {opt_cmd}).")
                        return
                    if time.time() > sim_stop:
                        break
                    time.sleep(0.01)

            # --- MAIL FROM ---
            code, msg = simulated_smtp.mail(mail_from)
            sim_stop = time.time() + mandatory_alloc.get("mail_from", 0)
            record["wait_stage"] = "mail_from"
            while True:
                if stop_event.is_set():
                    record["response_code"], record["status_code"], record["response_result"], record["end_time"], record["flag"] = \
                        finalize_session(simulated_smtp, "mail_from", mail_from, rcpt_to)
                    log_f.write(json.dumps(record) + "\n")
                    print(f"[+SIM] {server_name} completed (interrupted during mail_from).")
                    return
                if time.time() > sim_stop:
                    break
                time.sleep(0.01)

            # --- RCPT TO (multiple recipients generated by loop) ---
            last_rcpt = rcpt_to
            for i in range(rcpt_loop):
                last_rcpt = f"{random_alnum(5)}_TEST_@{random.choice(domains)}"
                code, msg = simulated_smtp.rcpt(last_rcpt)
                # small pause
                time.sleep(0.01)

            sim_stop = time.time() + mandatory_alloc.get("rcpt_to", 0)
            record["wait_stage"] = "rcpt_to"
            while True:
                if stop_event.is_set():
                    record["response_code"], record["status_code"], record["response_result"], record["end_time"], record["flag"] = \
                        finalize_session(simulated_smtp, "rcpt_to", mail_from, last_rcpt)
                    log_f.write(json.dumps(record) + "\n")
                    print(f"[+SIM] {server_name} completed (interrupted during rcpt_to).")
                    return
                if time.time() > sim_stop:
                    break

            # --- DATA command ---
            simulated_smtp.putcmd("DATA")
            code, msg = simulated_smtp.getreply()

            sim_stop = time.time() + mandatory_alloc.get("data", 0)
            record["wait_stage"] = "data"
            while True:
                if stop_event.is_set():
                    record["response_code"], record["status_code"], record["response_result"], record["end_time"], record["flag"] = \
                        finalize_session(simulated_smtp, "data", mail_from, last_rcpt)
                    log_f.write(json.dumps(record) + "\n")
                    print(f"[+SIM] {server_name} completed (interrupted during data).")
                    return
                if time.time() > sim_stop:
                    break
                time.sleep(0.01)

            # --- Headers & content stages ---
            simulated_smtp.send(f"From: {mail_from}\r\n")
            sim_stop = time.time() + mandatory_alloc.get("from", 0)
            record["wait_stage"] = "from"
            while True:
                if stop_event.is_set():
                    record["response_code"], record["status_code"], record["response_result"], record["end_time"], record["flag"] = \
                        finalize_session(simulated_smtp, "from", mail_from, last_rcpt)
                    log_f.write(json.dumps(record) + "\n")
                    print(f"[+SIM] {server_name} completed (interrupted during from).")
                    return
                if time.time() > sim_stop:
                    break

            simulated_smtp.send(f"To: {last_rcpt}\r\n")
            sim_stop = time.time() + mandatory_alloc.get("to", 0)
            record["wait_stage"] = "to"
            while True:
                if stop_event.is_set():
                    record["response_code"], record["status_code"], record["response_result"], record["end_time"], record["flag"] = \
                        finalize_session(simulated_smtp, "to", mail_from, last_rcpt)
                    log_f.write(json.dumps(record) + "\n")
                    print(f"[+SIM] {server_name} completed (interrupted during to).")
                    return
                if time.time() > sim_stop:
                    break

            simulated_smtp.send("Subject: SIMULATED_TEST\r\n")
            simulated_smtp.send(f"Message-ID: {generate_message_id(test_domain)}\r\n\r\n")
            simulated_smtp.send("SIMULATED BODY\r\n")

            sim_stop = time.time() + mandatory_alloc.get("content", 0)
            record["wait_stage"] = "content"
            while True:
                if stop_event.is_set():
                    record["response_code"], record["status_code"], record["response_result"], record["end_time"], record["flag"] = \
                        finalize_session(simulated_smtp, "content", mail_from, last_rcpt)
                    log_f.write(json.dumps(record) + "\n")
                    print(f"[+SIM] {server_name} completed (interrupted during content).")
                    return
                if time.time() > sim_stop:
                    break
                time.sleep(0.01)

            # If we reach here without interruption, the simulated session "timed out" before final termination
            record["flag"] = "timeout"
            record["response_result"] = "Simulated session timed out before finalization"
            record["end_time"] = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
            log_f.write(json.dumps(record) + "\n")
            print(f"[INFO] {server_name} simulation ended by timeout.")
            return

        except Exception as e:
            record["flag"] = "error"
            record["response_result"] = str(e)
            record["end_time"] = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")[:-3]
            log_f.write(json.dumps(record) + "\n")
            print(f"[ERROR] {server_name} unexpected exception: {e}")
            return

# ---------------------------------------------------------------------
# Lightweight activity test (purely local)
# ---------------------------------------------------------------------
def activity_probe(server_name: str) -> Tuple[bool, str]:
    """
    Very light-weight check to decide whether a server profile is likely usable.
    Here it simply returns True most of the time to mimic 'active' servers.
    """
    # Simulate that most servers are active (95% chance)
    return (random.random() < 0.95), server_name

# ---------------------------------------------------------------------
# Helper monitor process to set an event when it's time to stop a worker
# ---------------------------------------------------------------------
def schedule_stop_event(stop_event: multiprocessing.Event, stop_time: datetime.datetime, proc_name: str):
    """Set the multiprocessing.Event when stop_time is reached (no network ops)."""
    while datetime.datetime.now() < stop_time:
        # busy-wait is acceptable for short simulations; we keep it tiny
        time.sleep(0.05)
    stop_event.set()
    print(f"[SCHEDULER] {proc_name} ready to trigger simulated pulse at {stop_time.isoformat()}")

# ---------------------------------------------------------------------
# Main function: orchestrates simulation across multiple processes
# ---------------------------------------------------------------------
def main(argv: List[str]):
    parser = argparse.ArgumentParser(description="Offline bounce-pulse simulator (safe)")
    parser.add_argument("input", help="JSON config file describing synthetic bounce server profiles")
    parser.add_argument("output", help="Output log file (JSON Lines)")
    parser.add_argument("-r", "--attack-rate", help="(seconds) rate between starting processes", default=1.0, type=float)
    parser.add_argument("-n", "--server-num", help="number of servers to coordinate (int)", default=1, type=int)
    parser.add_argument("-e", "--victim-email", help="victim email address (used only as a label)", default="test@example.local", type=str)
    parser.add_argument("-s", "--victim-server", help="victim server (unused in offline sim)", default="none", type=str)
    parser.add_argument("-t", "--attack-time", help="target attack time in format YYYY-MM-DD-HH-MM-SS-fff", required=True, type=str)
    parser.add_argument("-l", "--loop-num", help="number of recipient addresses simulated per session", default=1, type=int)

    parsed = parser.parse_args(argv)

    # load config
    with open(parsed.input, "r", encoding="utf-8") as f:
        config = json.load(f)

    print("[INFO] Loaded synthetic server profiles from input config.")

    # Build internal profile dict (safe copy)
    server_profiles: Dict[str, Dict] = {}
    for key, val in config.items():
        # minimal sanitization and defaults
        server_profiles[key] = {
            "time_attack_bounce": val.get("time_attack_bounce", 0),
            "time_bounce_process": val.get("time_bounce_process", 0),
            "time_bounce_victim": val.get("time_bounce_victim", 0),
            "country": val.get("country", "unlisted"),
            "mandatory_command_dict": val.get("mandatory_command_dict", {}),
            "optional_command_num_dict": val.get("optional_command_num_dict", {}),
            "optional_command_time_dict": val.get("optional_command_time_dict", {}),
            "max_timeout": val.get("max_timeout", 300),
            "domain_list": val.get("domain_list", ["example.local"]),
            # behavior can be extended for advanced simulated replies
            "behavior": val.get("behavior", {}),
        }

    # parse end_time (target attack time)
    try:
        end_time = datetime.datetime.strptime(parsed.attack_time, "%Y-%m-%d-%H-%M-%S-%f")
    except Exception as e:
        print("[ERROR] attack-time format must be YYYY-MM-DD-HH-MM-SS-fff")
        raise

    # Candidate servers: filter those that can be scheduled in the time window
    now = datetime.datetime.now()
    window_seconds = int((end_time - now).total_seconds())

    candidate_servers: List[str] = []
    for sname, profile in server_profiles.items():
        ok, _, _ = evaluate_server_timing(profile, window_seconds)
        if ok:
            candidate_servers.append(sname)

    if not candidate_servers:
        print("[WARN] No candidate servers can be scheduled in the provided time window.")
        return

    random.shuffle(candidate_servers)

    # select a subset for the activity test (we simulate activity)
    # If server-num larger than candidates, sample with repetition is avoided: cap to available
    desired_count = min(parsed.server_num, len(candidate_servers))
    sampled = random.sample(candidate_servers, desired_count)

    # optional: run lightweight local 'activity' probes (simulated)
    active_list = []
    for s in sampled:
        alive, name = activity_probe(s)
        if alive:
            active_list.append(name)

    if len(active_list) < desired_count:
        print(f"[INFO] fewer active servers than requested: using {len(active_list)} servers.")
        selected_servers = active_list
    else:
        selected_servers = active_list

    # prepare multiprocessing events and worker processes
    events = [multiprocessing.Event() for _ in selected_servers]
    procs: List[multiprocessing.Process] = []

    # Launch worker processes
    for idx, server_name in enumerate(selected_servers):
        p = multiprocessing.Process(
            target=simulate_session,
            args=(
                parsed.victim_email,
                server_name,
                server_profiles[server_name],
                parsed.output,
                events[idx],
                end_time,
                parsed.loop_num
            )
        )
        p.start()
        procs.append(p)
        # stagger start to simulate attacker connection rate (but keep local-only)
        time.sleep(parsed.attack_rate)

    # compute stop times per server based on server profile's bounce processing time
    stop_times = []
    for idx, server_name in enumerate(selected_servers):
        process_delay = server_profiles[server_name].get("time_bounce_process", 0)
        stop_time = end_time - datetime.timedelta(seconds=process_delay)
        stop_times.append(stop_time)

    # launch scheduler processes that will set the event at the correct time
    schedulers = []
    for idx, evt in enumerate(events):
        proc_name = f"Scheduler-{idx+1}:{selected_servers[idx]}"
        t = multiprocessing.Process(target=schedule_stop_event, args=(evt, stop_times[idx], proc_name))
        t.start()
        schedulers.append(t)

    # wait for all worker processes to finish
    for p in procs:
        p.join()

    # terminate schedulers (they should exit after setting the events)
    for s in schedulers:
        s.join()

    print("[DONE] Offline simulation finished. See output log for JSON lines.")

if __name__ == "__main__":
    main(sys.argv[1:])
