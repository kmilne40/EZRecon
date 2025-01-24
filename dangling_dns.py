# dangling_dns.py
import curses
import sys
import logging
import subprocess
import requests
import re
from concurrent.futures import ThreadPoolExecutor

# If you want the spinner and display_text from your "utils.py", import them:
# from utils import Spinner, display_text

# For this example, we'll keep it simple and just print lines in the curses window.
# If you prefer pagination, you can adapt "display_text(...)" from utils.

def run_subfinder(domain):
    """
    Run subfinder to enumerate subdomains.
    Requires subfinder installed and in the PATH.
    """
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode != 0:
            return [], f"Error running subfinder: {result.stderr}"
        return result.stdout.splitlines(), None
    except FileNotFoundError:
        return [], "Error: subfinder not found. Make sure it is installed and in your PATH."

def check_dangling(subdomain):
    """Check if a subdomain might be dangling based on common error strings."""
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        content = response.text
        indicators = [
            "NoSuchBucket",        # AWS S3
            "NoSuchDomain",        # AWS Route53
            "NoSuchHost",          # General
            "doesn\u2019t exist",  # General
            "Heroku | No such app",# Heroku
            "404 Not Found",       # Generic
        ]
        for indicator in indicators:
            if indicator in content:
                return (subdomain, True)
        return (subdomain, False)
    except requests.exceptions.RequestException:
        return (subdomain, False)

def dangling_dns_check(stdscr):
    """
    Curses-based function for checking dangling DNS.
    Asks for a domain, runs subfinder, checks each subdomain for dangling references,
    and displays results in the curses UI.
    """
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter the domain name to check for dangling DNS: ")
        curses.echo()
        domain = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not domain:
            stdscr.addstr(1, 2, "No domain entered. Press any key to return...")
            stdscr.getch()
            return

        # If you have a spinner in utils, you can use it here:
        # spinner = Spinner(stdscr, "Enumerating subdomains")
        # spinner.start()

        subdomains, error_msg = run_subfinder(domain)
        # spinner.stop()

        # Display any subfinder errors:
        if error_msg:
            stdscr.attron(curses.color_pair(5))  # Typically red for errors
            stdscr.addstr(1, 2, error_msg)
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        if not subdomains:
            stdscr.addstr(1, 2, "No subdomains found.")
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        stdscr.addstr(1, 2, f"Found {len(subdomains)} subdomains for {domain}. Checking for dangling DNS...\n")

        # spinner = Spinner(stdscr, "Checking for dangling DNS")
        # spinner.start()

        # We can check subdomains in parallel
        dangling = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_dangling, subdomains)
            for (sub, is_dangling) in results:
                if is_dangling:
                    dangling.append(sub)

        # spinner.stop()

        line_offset = 3
        if dangling:
            stdscr.attron(curses.color_pair(4))  # Green or highlight color
            stdscr.addstr(line_offset, 2, "Potential dangling domains detected:")
            stdscr.attroff(curses.color_pair(4))
            line_offset += 2
            for d in dangling:
                stdscr.addstr(line_offset, 4, f"- {d}")
                line_offset += 1
        else:
            stdscr.addstr(line_offset, 2, "No dangling domains detected.")
            line_offset += 2

        stdscr.addstr(line_offset + 1, 2, "Press any key to return to the menu...")
        stdscr.getch()
        curses.curs_set(0)

    except Exception as e:
        logging.exception("Error in dangling_dns_check function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)
