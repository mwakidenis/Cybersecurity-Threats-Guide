#!/usr/bin/env python3
"""
Email Filters for Phishing Prevention

This script configures email filtering rules for various mail servers
to block phishing and spam emails.
"""

import os
import sys
import re
import json
import argparse
import subprocess
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

class EmailFilterConfig:
    """
    Email Filter Configuration System
    """
    
    def __init__(self):
        self.filters = {
            'spf': [],
            'dkim': [],
            'dmarc': [],
            'content': [],
            'attachment': [],
            'header': [],
            'rate_limit': []
        }
        
    def generate_postfix_filters(self, domain):
        """Generate Postfix filter rules"""
        filters = f"""
# Postfix Filter Rules for {domain}
# Generated on {datetime.now()}

# ============================================
# HELO/EHLO Restrictions
# ============================================
smtpd_helo_required = yes
smtpd_helo_restrictions = 
    permit_mynetworks,
    reject_invalid_helo_hostname,
    reject_non_fqdn_helo_hostname,
    reject_unknown_helo_hostname

# ============================================
# Sender Restrictions
# ============================================
smtpd_sender_restrictions = 
    permit_mynetworks,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain,
    reject_authenticated_sender_login_mismatch,
    reject_sender_login_mismatch

# ============================================
# Recipient Restrictions
# ============================================
smtpd_recipient_restrictions = 
    permit_mynetworks,
    reject_unauth_destination,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
    check_policy_service unix:private/policy-spf

# ============================================
# Content Filtering
# ============================================
# Enable content filter
content_filter = smtp-amavis:[127.0.0.1]:10024

# ============================================
# Rate Limiting
# ============================================
# Limit connections per client
smtpd_client_connection_rate_limit = 10
smtpd_client_message_rate_limit = 100
smtpd_client_recipient_rate_limit = 100

# ============================================
# SPF Configuration
# ============================================
# Install postfix-policyd-spf-perl
policy-spf_time_limit = 3600
smtpd_recipient_restrictions += 
    check_policy_service unix:private/policyd-spf

# ============================================
# RBL Filters
# ============================================
smtpd_recipient_restrictions += 
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net,
    reject_rbl_client cbl.abuseat.org,
    reject_rbl_client dnsbl.sorbs.net

# ============================================
# Custom Header Checks
# ============================================
header_checks = regexp:/etc/postfix/header_checks

# /etc/postfix/header_checks content:
/^Subject:.*\b(urgent|verify|account|suspended)\b/i REJECT Suspicious subject
/^From:.*@(?!{domain})/i REJECT Unauthorized sender domain
"""
        return filters
    
    def generate_header_checks(self):
        """Generate Postfix header check rules"""
        rules = """#
# Postfix header check rules
# Place in /etc/postfix/header_checks
#

# ============================================
# Subject line patterns
# ============================================
/^Subject:.*\burrent\b/i                   REJECT Spam keyword
/^Subject:.*\bimmediate action\b/i         REJECT Spam keyword
/^Subject:.*\baccount.*suspended\b/i       REJECT Spam keyword
/^Subject:.*\bsecurity alert\b/i           REJECT Spam keyword
/^Subject:.*\bverify.*account\b/i          REJECT Spam keyword
/^Subject:.*\bunusual activity\b/i         REJECT Spam keyword
/^Subject:.*\bclick here\b/i                REJECT Spam keyword
/^Subject:.*\bwin.*prize\b/i                REJECT Spam keyword
/^Subject:.*\blottery\b/i                   REJECT Spam keyword
/^Subject:.*\binheritance\b/i               REJECT Spam keyword
/^Subject:.*\bwire transfer\b/i             REJECT Spam keyword
/^Subject:.*\bgift card\b/i                 REJECT Spam keyword
/^Subject:.*\bitunes\b/i                     REJECT Spam keyword
/^Subject:.*\bamazon\b/i                     REJECT Spam keyword
/^Subject:.*\bpaypal\b/i                     REJECT Spam keyword
/^Subject:.*\bnetflix\b/i                    REJECT Spam keyword
/^Subject:.*\bmicrosoft\b/i                  REJECT Spam keyword
/^Subject:.*\bapple\b/i                      REJECT Spam keyword

# ============================================
# From header patterns
# ============================================
/^From:.*@.*\.tk\b/i                        REJECT Suspicious TLD
/^From:.*@.*\.ml\b/i                        REJECT Suspicious TLD
/^From:.*@.*\.ga\b/i                        REJECT Suspicious TLD
/^From:.*@.*\.cf\b/i                        REJECT Suspicious TLD
/^From:.*@.*\.gq\b/i                        REJECT Suspicious TLD
/^From:.*@.*\.xyz\b/i                       REJECT Suspicious TLD
/^From:.*@.*\.top\b/i                       REJECT Suspicious TLD
/^From:.*@.*\.win\b/i                       REJECT Suspicious TLD
/^From:.*@.*\.bid\b/i                       REJECT Suspicious TLD
/^From:.*@.*\.trade\b/i                     REJECT Suspicious TLD

# ============================================
# Spoofed domains
# ============================================
/^From:.*@.*paypa[li]\.com?/i               REJECT Possible PayPal spoof
/^From:.*@.*paypa[li]\.net?/i               REJECT Possible PayPal spoof
/^From:.*@.*amaz[o0]n\.[a-z]+/i             REJECT Possible Amazon spoof
/^From:.*@.*micr0s0ft\.[a-z]+/i             REJECT Possible Microsoft spoof
/^From:.*@.*g00gle\.[a-z]+/i                REJECT Possible Google spoof
/^From:.*@.*faceb00k\.[a-z]+/i              REJECT Possible Facebook spoof
/^From:.*@.*appIe\.[a-z]+/i                 REJECT Possible Apple spoof
/^From:.*@.*netfl1x\.[a-z]+/i               REJECT Possible Netflix spoof

# ============================================
# Attachment warnings
# ============================================
/^Content-Type:.*name=.*\.exe/i              WARNING Executable attachment
/^Content-Type:.*name=.*\.scr/i              WARNING Screensaver attachment
/^Content-Type:.*name=.*\.bat/i              WARNING Batch file attachment
/^Content-Type:.*name=.*\.cmd/i              WARNING Command file attachment
/^Content-Type:.*name=.*\.vbs/i              WARNING VBScript attachment
/^Content-Type:.*name=.*\.js/i               WARNING JavaScript attachment
/^Content-Type:.*name=.*\.jar/i              WARNING Java attachment
/^Content-Type:.*name=.*\.docm/i             WARNING Macro-enabled document
/^Content-Type:.*name=.*\.xlsm/i             WARNING Macro-enabled spreadsheet
/^Content-Type:.*name=.*\.pptm/i             WARNING Macro-enabled presentation
"""
        return rules
    
    def generate_spf_record(self, domain, ip_ranges=None):
        """Generate SPF record"""
        if ip_ranges is None:
            ip_ranges = ['include:_spf.google.com']
        
        spf = f"v=spf1 {' '.join(ip_ranges)} -all"
        return spf
    
    def generate_dkim_record(self, domain, selector='default', key_length=2048):
        """Generate DKIM record"""
        # Note: Actual key generation would be done separately
        dkim = f"v=DKIM1; h=sha256; k=rsa; p=YOUR_PUBLIC_KEY_HERE"
        return dkim
    
    def generate_dmarc_record(self, domain, policy='reject'):
        """Generate DMARC record"""
        dmarc = f"v=DMARC1; p={policy}; rua=mailto:dmarc@{domain}; ruf=mailto:dmarc@{domain}; fo=1; pct=100"
        return dmarc
    
    def generate_exim_filters(self):
        """Generate Exim filter rules"""
        filters = f"""
# Exim Filter Rules
# Generated on {datetime.now()}

# ============================================
# ACL before MAIL
# ============================================
acl_check_mail:
  deny message = HELO required before MAIL
       condition = $sender_helo_name is empty

# ============================================
# ACL before RCPT
# ============================================
acl_check_rcpt:
  accept hosts = :
  
  deny message = Rejected because $sender_host_address is in a black list at $dnslist_domain\n$dnslist_text
       dnslists = zen.spamhaus.org : bl.spamcop.net : dnsbl.sorbs.net
  
  warn message = X-Spam-Score: $spam_score_int
       spam = nobody/defer_ok

  # Rate limiting
  defer message = Too many connections from this IP
        ratelimit = 20 / 1h / per_conn / strict

# ============================================
# Router for spam filtering
# ============================================
spamcheck:
  driver = accept
  condition = ${if >{$spam_score_int}{50}{1}{0}}
  transport = spam_filter

# ============================================
# Transport for spam
# ============================================
spam_filter:
  driver = pipe
  command = /usr/bin/spamc -f -u $local_part@$domain
  return_output
"""
        return filters
    
    def generate_sieve_filters(self):
        """Generate Sieve filter rules (Dovecot)"""
        filters = f"""
# Sieve Filter Rules
# Generated on {datetime.now()}

require ["fileinto", "mailbox", "envelope", "regex", "variables"];

# ============================================
# Spam filtering
# ============================================
if anyof (
    header :contains "X-Spam-Flag" "YES",
    header :contains "X-Spam-Status" "Yes"
) {{
    fileinto "Spam";
    stop;
}}

# ============================================
# Suspicious sender domains
# ============================================
if address :domain :contains "From" [
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".win", ".bid", ".trade"
] {{
    fileinto "Spam/SuspiciousDomains";
    stop;
}}

# ============================================
# Urgent subject patterns
# ============================================
if header :regex "Subject" [
    ".*urgent.*",
    ".*immediate action.*",
    ".*account.*suspended.*",
    ".*security alert.*",
    ".*verify.*account.*",
    ".*unusual activity.*"
] {{
    fileinto "PotentialPhishing";
    stop;
}}

# ============================================
# Suspicious attachments
# ============================================
if anyof (
    header :contains "Content-Type" "name=.*\\.exe",
    header :contains "Content-Type" "name=.*\\.scr",
    header :contains "Content-Type" "name=.*\\.bat",
    header :contains "Content-Type" "name=.*\\.vbs",
    header :contains "Content-Type" "name=.*\\.js"
) {{
    fileinto "Quarantine/SuspiciousAttachments";
    stop;
}}

# ============================================
# Spoofed domains
# ============================================
if address :domain :matches "From" "*" {{
    set "domain" "${{1}}";
    
    # Check for common spoofs
    if string "${domain}" contains "paypa" {{
        if not string "${domain}" is "paypal.com" {{
            fileinto "Spam/SpoofedDomains";
            stop;
        }}
    }}
    
    if string "${domain}" contains "amaz" {{
        if not string "${domain}" is "amazon.com" {{
            fileinto "Spam/SpoofedDomains";
            stop;
        }}
    }}
}}

# ============================================
# Bulk emails folder
# ============================================
if anyof (
    header :contains "List-Unsubscribe" "",
    header :contains "Precedence" "bulk",
    header :contains "Precedence" "list"
) {{
    fileinto "Bulk";
    stop;
}}

# ============================================
# Newsletter folder
# ============================================
if anyof (
    header :contains "Subject" "newsletter",
    header :contains "Subject" "weekly digest",
    header :contains "X-Mailer" "MailChimp",
    header :contains "X-Mailer" "ConstantContact"
) {{
    fileinto "Newsletters";
    stop;
}}

# ============================================
# Notifications folder
# ============================================
if anyof (
    envelope :contains "From" "noreply@",
    envelope :contains "From" "no-reply@",
    envelope :contains "From" "notifications@"
) {{
    fileinto "Notifications";
    stop;
}}

# ============================================
# Default action
# ============================================
# Keep in inbox
keep;
"""
        return filters
    
    def generate_rspamd_config(self):
        """Generate Rspamd configuration"""
        config = f"""
# Rspamd Configuration
# Generated on {datetime.now()}

# ============================================
# Main configuration
# ============================================
worker {
    type = "normal";
    bind_socket = "*:11333";
    bind_socket = "localhost:11334";
    count = 4;
}

worker {
    type = "controller";
    bind_socket = "localhost:11334";
    count = 1;
    secure_ip = "127.0.0.1";
    secure_ip = "::1";
    password = "admin";
}

# ============================================
# Modules
# ============================================
surbl {
    enabled = true;
    symbols = {
        "SURBL_BLOCKED"
