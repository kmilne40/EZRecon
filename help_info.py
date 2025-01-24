# help_info.py
import curses
import sys
import logging

# If you have a pagination function like 'display_text' in utils.py, import it:
# from utils import display_text

def help_info(stdscr):
    """
    Displays an overview of each tool's purpose using curses.
    Uses a multi-line string (triple quotes) that is properly closed.
    """
    try:
        curses.curs_set(0)
        stdscr.clear()

        # Example multi-line help text. Make sure every triple-quote is matched.
        help_text = """\
================== RECCY TOOLKIT HELP ==================

F1: Google Dork
    Integrates Google Custom Search to find references, emails,
    and subdomains for a given domain.

F2: DNS Lookup (A)
    Performs a DNS A-record lookup for the specified domain.

F3: MX Lookup
    Retrieves mail-exchange (MX) records for the given domain.

F4: NS Lookup
    Retrieves name server (NS) records.

F5: SOA Lookup
    Shows the domain's Start of Authority (SOA) record.

F6: Reverse DNS Lookup
    Reverses an IP to find its associated domain name.

F7: WHOIS Lookup
    Displays whois info (registrar, contact details, etc.) for a domain.

F8: Get All Information
    Aggregates A, MX, NS, SOA, Reverse DNS, WHOIS in one place.

F9: Perform Zone Transfer
    Attempts a zone transfer (AXFR) from the domain's name servers.

F10: Email Scraper
    Crawls a website and extracts potential email addresses.

F11: Brute Force Subdomains
    Uses a wordlist to identify subdomains for a domain.

F12: Port Scan & Banner Grab
    Scans specified ports on a domain/IP and fetches banners.

A: Shodan Lookup
    Provides sub-menu options for Shodan (search, host info).

D: Dangling DNS Check
    Enumerates subdomains (via subfinder) and checks for orphaned hosting.

H: Help / About Tools
    Displays this help screen.

X: Exit
    Exits the RECCY Toolkit.
"""

        ################################################################
        # If you have a display_text(stdscr, text) function in utils.py,
        # you can call it here. Otherwise, we'll just show how to do
        # a simple direct print that truncates/wraps lines.
        ################################################################

        # BASIC approach: write lines with basic safety checks
        h, w = stdscr.getmaxyx()
        lines = help_text.split("\n")

        row = 1
        for line in lines:
            # If at bottom, stop or paginate
            if row >= h - 2:
                break
            # Truncate if too long
            if len(line) > w - 2:
                line = line[: w - 5] + "..."
            stdscr.addstr(row, 2, line)
            row += 1

        stdscr.addstr(row + 1, 2, "Press any key to return to the menu...")
        stdscr.refresh()
        stdscr.getch()

    except Exception as e:
        logging.exception("Error in help_info function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)
