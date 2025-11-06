# CoordMail: Exploiting SMTP Timeout and Command Interaction to Coordinate Email Middleware for Convergence Amplification Attack

## simulate_attack Folder

coordmail.py provides code to simulate attacks, and config.json provides sample configuration files.



## email_middleware Folder

find_bounce_server.py and find_open_relay.py provides the code to discover the bounce email servers and open email relay servers.

sample_bounce_server.txt and sample_open_relay.txt provides the sampled dataset of email middleware we collected.



## detect_metrics Folder

check_timeout.py provides code to measure timeouts for SMTP commands supported by the middleware, and check_Non-mandatory_command.py provides code to measure middleware support for Non-mandatory SMTP commands.
