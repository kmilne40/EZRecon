import curses
import sys
import logging
import subprocess
import requests
from bs4 import BeautifulSoup
import dns.resolver
import dns.reversename
import dns.exception
import dns.query
import dns.zone
import socket
import re

from urllib.parse import urljoin

# For spinners, validations, table prints, etc.
from utils import (
    Spinner, is_valid_domain, is_valid_ip,
    print_table_custom, display_text
)

# 1. DNS Lookup (A)
def dns_lookup(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter domain name for DNS Lookup (A): ")
        curses.echo()
        domain = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not is_valid_domain(domain):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"Invalid domain format: {domain}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        try:
            answers = dns.resolver.resolve(domain, 'A')
            data = [(rdata.to_text(),) for rdata in answers]
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(1, 2, f"A records for {domain}:")
            stdscr.attroff(curses.color_pair(4))
            print_table_custom(data, ["IP Address"], stdscr, 3, 2)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"No A records found for {domain} or domain is invalid.")
            stdscr.attroff(curses.color_pair(5))
        except dns.exception.DNSException as e:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"DNS error: {e}")
            stdscr.attroff(curses.color_pair(5))

        stdscr.addstr(5 + len(data), 2, "Press any key to return to the menu...")
        stdscr.getch()
        curses.curs_set(0)
    except Exception as e:
        logging.exception("Error in dns_lookup function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

# 2. MX Lookup
def mx_lookup(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter domain name for MX Lookup: ")
        curses.echo()
        domain = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not is_valid_domain(domain):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"Invalid domain format: {domain}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        spf_records = []
        dmarc_records = []

        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = [(rdata.preference, rdata.exchange.to_text()) for rdata in answers]
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(1, 2, f"MX records for {domain}:")
            stdscr.attroff(curses.color_pair(4))
            print_table_custom(mx_records, ["Preference", "Mail Server"], stdscr, 3, 2)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"No MX records found for {domain} or domain is invalid.")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return
        except dns.exception.DNSException as e:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"DNS error: {e}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        # SPF records
        try:
            txt_answers = dns.resolver.resolve(domain, 'TXT')
            spf_records = [
                rdata.to_text().strip('"') for rdata in txt_answers
                if 'v=spf1' in rdata.to_text()
            ]
            if spf_records:
                stdscr.attron(curses.color_pair(4))
                stdscr.addstr(5 + len(mx_records), 2, "SPF Records:")
                stdscr.attroff(curses.color_pair(4))
                for idx, spf in enumerate(spf_records, start=6 + len(mx_records)):
                    stdscr.addstr(idx, 4, spf)
            else:
                stdscr.attron(curses.color_pair(5))
                stdscr.addstr(5 + len(mx_records), 2, "No SPF records found.")
                stdscr.attroff(curses.color_pair(5))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(5 + len(mx_records), 2, "No SPF records found or domain is invalid.")
            stdscr.attroff(curses.color_pair(5))
        except dns.exception.DNSException as e:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(5 + len(mx_records), 2, f"DNS error (SPF records): {e}")
            stdscr.attroff(curses.color_pair(5))

        # DMARC records
        dmarc_domain = f"_dmarc.{domain}"
        try:
            dmarc_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [rdata.to_text().strip('"') for rdata in dmarc_answers]
            if dmarc_records:
                start_line = 6 + len(mx_records) + len(spf_records)
                stdscr.attron(curses.color_pair(4))
                stdscr.addstr(start_line, 2, "DMARC Records:")
                stdscr.attroff(curses.color_pair(4))
                for idx, dmarc in enumerate(dmarc_records, start=start_line + 1):
                    stdscr.addstr(idx, 4, dmarc)
            else:
                stdscr.attron(curses.color_pair(5))
                stdscr.addstr(6 + len(mx_records), 2, "No DMARC records found.")
                stdscr.attroff(curses.color_pair(5))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(6 + len(mx_records), 2, "No DMARC records found or domain is invalid.")
            stdscr.attroff(curses.color_pair(5))
        except dns.exception.DNSException as e:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(6 + len(mx_records), 2, f"DNS error (DMARC records): {e}")
            stdscr.attroff(curses.color_pair(5))

        stdscr.addstr(
            8 + len(mx_records) + len(spf_records) + len(dmarc_records),
            2,
            "Press any key to return to the menu..."
        )
        stdscr.getch()
        curses.curs_set(0)
    except Exception as e:
        logging.exception("Error in mx_lookup function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

# 3. NS Lookup
def ns_lookup(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter domain name for NS Lookup: ")
        curses.echo()
        domain = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not is_valid_domain(domain):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"Invalid domain format: {domain}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        try:
            answers = dns.resolver.resolve(domain, 'NS')
            data = [(rdata.target.to_text(),) for rdata in answers]
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(1, 2, f"NS records for {domain}:")
            stdscr.attroff(curses.color_pair(4))
            print_table_custom(data, ["Name Server"], stdscr, 3, 2)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"No NS records found for {domain} or domain is invalid.")
            stdscr.attroff(curses.color_pair(5))
        except dns.exception.DNSException as e:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"DNS error: {e}")
            stdscr.attroff(curses.color_pair(5))

        stdscr.addstr(5 + len(data), 2, "Press any key to return to the menu...")
        stdscr.getch()
        curses.curs_set(0)
    except Exception as e:
        logging.exception("Error in ns_lookup function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

# 4. SOA Lookup
def soa_lookup(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter domain name for SOA Lookup: ")
        curses.echo()
        domain = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not is_valid_domain(domain):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"Invalid domain format: {domain}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        try:
            answers = dns.resolver.resolve(domain, 'SOA')
            data = [
                ("Primary Name Server", answers[0].mname.to_text()),
                ("Responsible Person", answers[0].rname.to_text()),
                ("Serial Number", answers[0].serial),
                ("Refresh Interval", answers[0].refresh),
                ("Retry Interval", answers[0].retry),
                ("Expire Limit", answers[0].expire),
                ("Minimum TTL", answers[0].minimum)
            ]
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(1, 2, f"SOA records for {domain}:")
            stdscr.attroff(curses.color_pair(4))
            for idx, (key, value) in enumerate(data, start=3):
                stdscr.addstr(idx, 4, f"{key}: {value}")
        except dns.resolver.NoAnswer:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"No SOA records found for {domain}.")
            stdscr.attroff(curses.color_pair(5))
        except dns.resolver.NXDOMAIN:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"The domain {domain} does not exist.")
            stdscr.attroff(curses.color_pair(5))
        except dns.exception.DNSException as e:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"DNS error (SOA records): {e}")
            stdscr.attroff(curses.color_pair(5))

        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the menu...")
        stdscr.getch()
        curses.curs_set(0)
    except Exception as e:
        logging.exception("Error in soa_lookup function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

# 5. Reverse DNS Lookup
def reverse_dns_lookup(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter IP address for Reverse DNS Lookup: ")
        curses.echo()
        ip_address = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not is_valid_ip(ip_address):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"Invalid IP address: {ip_address}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        try:
            rev_name = dns.reversename.from_address(ip_address)
            answers = dns.resolver.resolve(rev_name, 'PTR')
            data = [(str(rdata.target).rstrip("."),) for rdata in answers]
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(1, 2, f"PTR record for {ip_address}:")
            stdscr.attroff(curses.color_pair(4))
            print_table_custom(data, ["Domain Name"], stdscr, 3, 2)
        except dns.resolver.NoAnswer:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"No PTR records found for {ip_address}.")
            stdscr.attroff(curses.color_pair(5))
        except dns.resolver.NXDOMAIN:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"No reverse DNS record exists for {ip_address}.")
            stdscr.attroff(curses.color_pair(5))
        except dns.exception.DNSException as e:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"DNS error (PTR records): {e}")
            stdscr.attroff(curses.color_pair(5))

        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the menu...")
        stdscr.getch()
        curses.curs_set(0)
    except Exception as e:
        logging.exception("Error in reverse_dns_lookup function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

# 6. WHOIS Lookup
def whois_lookup(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter domain name for WHOIS Lookup: ")
        curses.echo()
        domain = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not domain:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, "No domain entered.")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        spinner = Spinner(stdscr, "Performing WHOIS lookup")
        spinner.start()

        try:
            whois_output = subprocess.check_output(
                ["whois", domain],
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15
            )
            spinner.stop()
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(1, 2, f"WHOIS Information for {domain}:\n\n")
            stdscr.attroff(curses.color_pair(4))
            display_text(stdscr, whois_output)
        except FileNotFoundError:
            spinner.stop()
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, "Error: The 'whois' command is not installed on this system.")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
        except subprocess.CalledProcessError as e:
            spinner.stop()
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"WHOIS command failed:\n{e.output}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
        except subprocess.TimeoutExpired:
            spinner.stop()
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, "WHOIS command timed out.")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
        except Exception as e:
            spinner.stop()
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"WHOIS lookup error occurred: {e}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()

    except Exception as e:
        logging.exception("Error in whois_lookup function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

# 7. Get All Information
def get_all_information(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter domain name to get all information: ")
        curses.echo()
        domain = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        from utils import Spinner  # local import to avoid circular refs
        spinner = Spinner(stdscr, "Gathering DNS and WHOIS information")

        if not is_valid_domain(domain):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"Invalid domain format: {domain}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        output = f"Gathering all information for {domain}...\n\n"
        spinner.start()

        # A Records
        import dns
        try:
            answers = dns.resolver.resolve(domain, 'A')
            a_records = [rdata.to_text() for rdata in answers]
            output += "A Records:\n" + "\n".join(a_records) + "\n\n"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            output += "No A records found or domain is invalid.\n\n"
        except dns.exception.DNSException as e:
            output += f"DNS error (A records): {e}\n\n"

        # MX Records
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = [f"{rdata.preference} {str(rdata.exchange).rstrip('.')}" for rdata in answers]
            output += "MX Records:\n" + "\n".join(mx_records) + "\n\n"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            output += "No MX records found.\n\n"
        except dns.exception.DNSException as e:
            output += f"DNS error (MX records): {e}\n\n"

        # NS Records
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            ns_records = [str(rdata.target).rstrip('.') for rdata in answers]
            output += "NS Records:\n" + "\n".join(ns_records) + "\n\n"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            output += "No NS records found.\n\n"
        except dns.exception.DNSException as e:
            output += f"DNS error (NS records): {e}\n\n"

        # SOA Records
        try:
            answers = dns.resolver.resolve(domain, 'SOA')
            soa_records = []
            for rdata in answers:
                soa_records.append(f"Primary Name Server: {rdata.mname.to_text()}")
                soa_records.append(f"Responsible Person: {rdata.rname.to_text()}")
                soa_records.append(f"Serial Number: {rdata.serial}")
                soa_records.append(f"Refresh Interval: {rdata.refresh}")
                soa_records.append(f"Retry Interval: {rdata.retry}")
                soa_records.append(f"Expire Limit: {rdata.expire}")
                soa_records.append(f"Minimum TTL: {rdata.minimum}")
            output += "SOA Records:\n" + "\n".join(soa_records) + "\n\n"
        except dns.resolver.NoAnswer:
            output += "No SOA records found.\n\n"
        except dns.resolver.NXDOMAIN:
            output += f"The domain {domain} does not exist.\n\n"
        except dns.exception.DNSException as e:
            output += f"DNS error (SOA records): {e}\n\n"

        # Reverse DNS (first A record)
        try:
            answers = dns.resolver.resolve(domain, 'A')
            first_ip = answers[0].to_text()
            rev_name = dns.reversename.from_address(first_ip)
            ptr_answers = dns.resolver.resolve(rev_name, 'PTR')
            ptr_records = [str(rdata.target).rstrip('.') for rdata in ptr_answers]
            output += f"Reverse DNS Lookup for {first_ip}:\n" + "\n".join(ptr_records) + "\n\n"
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, IndexError):
            output += "No PTR records found or no A records available.\n\n"
        except dns.exception.DNSException as e:
            output += f"DNS error (PTR records): {e}\n\n"

        # WHOIS
        import subprocess
        try:
            whois_output = subprocess.check_output(
                ["whois", domain],
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15
            )
            output += f"WHOIS Information for {domain}:\n" + whois_output + "\n\n"
        except FileNotFoundError:
            output += "Error: The 'whois' command is not installed on this system.\n\n"
        except subprocess.CalledProcessError as e:
            output += f"WHOIS command failed:\n{e.output}\n\n"
        except subprocess.TimeoutExpired:
            output += "WHOIS command timed out.\n\n"
        except Exception as e:
            output += f"WHOIS lookup error occurred: {e}\n\n"

        spinner.stop()

        stdscr.attron(curses.color_pair(4))
        display_text(stdscr, output)
        stdscr.attroff(curses.color_pair(4))

        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the menu...")
        stdscr.getch()
        curses.curs_set(0)
    except Exception as e:
        logging.exception("Error in get_all_information function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

# 8. Perform Zone Transfer
def perform_zone_transfer(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter domain name for Zone Transfer: ")
        curses.echo()
        domain = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not is_valid_domain(domain):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"Invalid domain format: {domain}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        import dns
        from utils import Spinner
        spinner = Spinner(stdscr, "Attempting zone transfer")
        spinner.start()

        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            ns_servers = [str(rdata.target).rstrip(".") for rdata in ns_records]
            successful = False
            zone_data = ""

            for ns in ns_servers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                    if zone:
                        zone_data = zone.to_text()
                        successful = True
                        break
                except dns.exception.DNSException as e:
                    logging.info(f"Zone transfer failed at {ns} for {domain}: {e}")
                    continue

            spinner.stop()

            if successful:
                stdscr.attron(curses.color_pair(4))
                stdscr.addstr(1, 2, f"Zone transfer successful with {ns}:\n\n")
                stdscr.attroff(curses.color_pair(4))
                display_text(stdscr, zone_data)
            else:
                stdscr.attron(curses.color_pair(5))
                stdscr.addstr(1, 2, "Zone transfer did not succeed with any name server.")
                stdscr.attroff(curses.color_pair(5))
                stdscr.addstr(3, 2, "Press any key to return to the menu...")
                stdscr.getch()
        except dns.resolver.NoAnswer:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"No NS records found for {domain}.")
            stdscr.attroff(curses.color_pair(5))
        except dns.resolver.NXDOMAIN:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"The domain {domain} does not exist.")
            stdscr.attroff(curses.color_pair(5))
        except dns.exception.DNSException as e:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"DNS error during zone transfer: {e}")
            stdscr.attroff(curses.color_pair(5))
        except Exception as e:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"Unexpected error during zone transfer: {e}")
            stdscr.attroff(curses.color_pair(5))

        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the menu...")
        stdscr.getch()
        curses.curs_set(0)
    except Exception as e:
        logging.exception("Error in perform_zone_transfer function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

# 9. Email Scraper
def email_scraper(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter the website URL to spider (e.g., https://example.com): ")
        curses.echo()
        base_url = stdscr.getstr(2, 2, 60).decode().strip()
        stdscr.addstr(3, 2, "Enter the spidering depth (e.g., 2): ")
        max_depth_input = stdscr.getstr(4, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        try:
            max_depth = int(max_depth_input)
        except ValueError:
            max_depth = 2
            stdscr.addstr(1, 2, "Invalid depth entered. Defaulting to 2.\n")

        visited_urls = set()
        emails_found = set()

        def extract_emails_from_page(url):
            import requests
            from bs4 import BeautifulSoup
            import re
            from urllib.parse import urljoin
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                page_emails = re.findall(
                    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
                    response.text
                )
                for email in page_emails:
                    emails_found.add(email)
                links = [urljoin(url, a.get('href')) for a in soup.find_all('a', href=True)]
                return links
            except Exception as e:
                logging.debug(f"Failed to fetch {url}: {e}")
                return []

        def spider_website(base_url, max_depth=2):
            queue = [(base_url, 0)]
            visited_urls.add(base_url)
            while queue:
                current_url, depth = queue.pop(0)
                if depth > max_depth:
                    continue
                new_links = extract_emails_from_page(current_url)
                for link in new_links:
                    if link.startswith(base_url) and link not in visited_urls:
                        visited_urls.add(link)
                        queue.append((link, depth + 1))

        stdscr.addstr(1, 2, f"[*] Starting spidering for: {base_url} with depth: {max_depth}\n")
        stdscr.refresh()

        from utils import Spinner
        spinner = Spinner(stdscr, "Spidering website")
        spinner.start()

        spider_website(base_url, max_depth)

        spinner.stop()

        stdscr.addstr(3 + max_depth, 2, "\nEmails found:\n")
        if emails_found:
            for idx, email in enumerate(emails_found, start=1):
                stdscr.addstr(4 + max_depth + idx, 4, email)
        else:
            stdscr.addstr(4 + max_depth, 4, "No emails found.")

        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the menu...")
        stdscr.getch()
        curses.curs_set(0)
    except Exception as e:
        logging.exception("Error in email_scraper function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

# 10. Brute Force Subdomains
def brute_force_subdomains(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter domain name for Subdomain Brute Force: ")
        curses.echo()
        domain = stdscr.getstr(2, 2, 60).decode().strip()
        stdscr.addstr(3, 2, "Enter path to subdomain wordlist (e.g., subdomains.txt): ")
        wordlist_path = stdscr.getstr(4, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        from utils import Spinner

        if not is_valid_domain(domain):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"Warning: {domain} might not pass regex validation.\n")
            stdscr.attroff(curses.color_pair(5))

        stdscr.addstr(2, 2, f"[*] Starting subdomain brute force for: {domain}")
        stdscr.addstr(3, 2, f"[*] Using subdomain wordlist: {wordlist_path}\n")
        stdscr.refresh()

        try:
            with open(wordlist_path, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(5, 2, f"Wordlist file not found: {wordlist_path}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(6, 2, "Press any key to return to the menu...")
            stdscr.getch()
            curses.curs_set(0)
            return
        except Exception as e:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(5, 2, f"Error reading subdomain file '{wordlist_path}': {e}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(6, 2, "Press any key to return to the menu...")
            stdscr.getch()
            curses.curs_set(0)
            return

        found_subdomains = []

        spinner = Spinner(stdscr, "Brute forcing subdomains")
        spinner.start()

        import dns
        for sub in subdomains:
            brute_domain = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(brute_domain, 'A')
                ip_addresses = [rdata.address for rdata in answers]
                found_subdomains.append((brute_domain, ", ".join(ip_addresses)))
                stdscr.addstr(5 + len(found_subdomains), 2, f"Found: {brute_domain} -> {', '.join(ip_addresses)}")
                stdscr.refresh()
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.exception.DNSException as ex:
                logging.debug(f"DNS error for subdomain {brute_domain}: {ex}")
                continue

        spinner.stop()

        stdscr.addstr(5 + len(found_subdomains) + 2, 2, "Discovered subdomains:\n")
        if found_subdomains:
            for idx, (sub, ips) in enumerate(found_subdomains, start=1):
                stdscr.addstr(6 + len(found_subdomains) + idx, 4, f"{sub}: {ips}")
        else:
            stdscr.addstr(6 + len(found_subdomains), 4, "No subdomains were discovered.")

        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the menu...")
        stdscr.getch()
        curses.curs_set(0)
    except Exception as e:
        logging.exception("Error in brute_force_subdomains function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

# 11. Port Scan & Banner Grab
def port_scan_banner_grab(stdscr):
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter domain or IP to scan: ")
        curses.echo()
        host = stdscr.getstr(2, 2, 60).decode().strip()
        stdscr.addstr(3, 2, "Enter comma-delimited ports to scan (e.g., 22,80,443): ")
        ports_str = stdscr.getstr(4, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        ports = []
        try:
            for p in ports_str.split(","):
                p = p.strip()
                if p.isdigit():
                    ports.append(int(p))
        except:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(5, 2, "Invalid ports specified. Exiting.")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(6, 2, "Press any key to return to the menu...")
            stdscr.getch()
            curses.curs_set(0)
            return

        stdscr.addstr(1, 2, f"\nScanning {host} for ports: {ports}\n")
        stdscr.refresh()

        open_ports = []

        from utils import Spinner
        spinner = Spinner(stdscr, "Scanning ports")
        spinner.start()

        import socket
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                    stdscr.addstr(3 + len(open_ports), 2, f"Port {port} is OPEN. Attempting banner grab...")
                    stdscr.refresh()
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024)
                        stdscr.addstr(4 + len(open_ports), 4, f"  Banner: {banner.decode(errors='replace')}")
                    except Exception as e:
                        stdscr.addstr(4 + len(open_ports), 4, f"  Could not grab banner: {e}")
                sock.close()
            except Exception:
                continue

        spinner.stop()

        if open_ports:
            stdscr.attron(curses.color_pair(4))
            stdscr.addstr(6 + len(open_ports), 2, "\nOpen ports found:")
            stdscr.attroff(curses.color_pair(4))
            stdscr.addstr(7 + len(open_ports), 4, ", ".join(map(str, open_ports)))
        else:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(6 + len(open_ports), 2, "\nNo open ports found among the specified ports.")
            stdscr.attroff(curses.color_pair(5))

        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the menu...")
        stdscr.getch()
        curses.curs_set(0)
    except Exception as e:
        logging.exception("Error in port_scan_banner_grab function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)
