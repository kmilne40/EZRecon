# menu.py

import curses
import sys
import logging

# Import your local modules as actual function references:
from google_dork import google_dork
from recon_functions import (
    dns_lookup,
    mx_lookup,
    ns_lookup,
    soa_lookup,
    reverse_dns_lookup,
    whois_lookup,
    get_all_information,
    perform_zone_transfer,
    email_scraper,
    brute_force_subdomains,
    port_scan_banner_grab
)
from shodan_functions import shodan_lookup_submenu
from dangling_dns import dangling_dns_check
from help_info import help_info
from nmap_functions import nmap_lookup_submenu
from hydra_functions import hydra_lookup_submenu
from nmap_mymap import nmap_mymap_submenu
from analysis import analyze_data_mindmap

###############################################################################
# If you have these in a utils.py, you can remove these stubs:
###############################################################################
def init_colors():
    """Initialize curses color pairs."""
    try:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)  # highlighted
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)  # normal
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLUE)  # header
        curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)  # success
        curses.init_pair(5, curses.COLOR_RED, curses.COLOR_BLACK)    # error
    except:
        pass

def exit_program(stdscr):
    curses.endwin()
    sys.exit()

###############################################################################
# Store the ACTUAL function objects, NOT strings:
###############################################################################
MENU_OPTIONS_LIST = [
    ("F1",   "Google Dork",                 google_dork),
    ("F2",   "Perform DNS Lookup (A)",      dns_lookup),
    ("F3",   "Perform MX Lookup",           mx_lookup),
    ("F4",   "Perform NS Lookup",           ns_lookup),
    ("F5",   "Perform SOA Lookup",          soa_lookup),
    ("F6",   "Perform Reverse DNS Lookup",  reverse_dns_lookup),
    ("F7",   "WHOIS Lookup",                whois_lookup),
    ("F8",   "Get All Information",         get_all_information),
    ("F9",   "Perform Zone Transfer",       perform_zone_transfer),
    ("F10",  "Email Scraper",               email_scraper),
    ("F11",  "Brute Force Subdomains",      brute_force_subdomains),

    ("A",    "Shodan Lookup",               shodan_lookup_submenu),
    ("D",    "Dangling DNS Check",          dangling_dns_check),

    # We'll keep "H" for Help Info, but give Hydra a different letter (e.g., "R")
    ("H",    "Help / About Tools",          help_info),
    ("R",    "Hydra Functions",             hydra_lookup_submenu),

    ("N",    "Nmap Port Scanner",           nmap_lookup_submenu),
    ("Z",    "Analyze Data",                analyze_data_mindmap),
    ("X",    "Exit",                        exit_program)
]

def draw_menu(stdscr, selected_idx):
    stdscr.clear()
    height, width = stdscr.getmaxyx()

    # Draw a box
    stdscr.border(0)

    # Add header
    header = "===== RECCY TOOLKIT (ISPF-Style) ====="
    stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
    stdscr.addstr(1, width // 2 - len(header) // 2, header)
    stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

    # Add menu title
    menu_title = "Menu Options"
    stdscr.attron(curses.color_pair(2) | curses.A_UNDERLINE)
    stdscr.addstr(3, 2, menu_title)
    stdscr.attroff(curses.color_pair(2) | curses.A_UNDERLINE)

    # List items
    for i, (menu_key, desc, func) in enumerate(MENU_OPTIONS_LIST):
        x = 4
        y = 5 + i
        if i == selected_idx:
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(y, x, f"> {menu_key}: {desc}")
            stdscr.attroff(curses.color_pair(1))
        else:
            if menu_key.upper() in ["X", "A", "D", "H", "R"]:
                stdscr.attron(curses.color_pair(5))  # e.g. red for single-letter
                stdscr.addstr(y, x, f"  {menu_key}: {desc}")
                stdscr.attroff(curses.color_pair(5))
            else:
                stdscr.attron(curses.color_pair(2))
                stdscr.addstr(y, x, f"  {menu_key}: {desc}")
                stdscr.attroff(curses.color_pair(2))

    # Add footer
    footer = "Use Arrow Keys, Enter to Select, F1-F12 or Single Letters (A/D/H/R/X) to Activate"
    stdscr.attron(curses.color_pair(3))
    stdscr.addstr(height - 2, width // 2 - len(footer) // 2, footer)
    stdscr.attroff(curses.color_pair(3))

    stdscr.refresh()

def main_menu(stdscr):
    """
    Main loop for the menu:
      - Initialize curses colors
      - Track highlighted menu item
      - Respond to keys (arrow keys, F1-F12, letters, Enter, etc.)
    """
    try:
        init_colors()
        curses.curs_set(0)
        stdscr.keypad(True)

        selected_idx = 0

        while True:
            draw_menu(stdscr, selected_idx)
            key = stdscr.getch()

            # 'x' => exit
            if key in [ord('x'), ord('X')]:
                exit_program(stdscr)

            # Handle function keys F1-F12
            elif key in range(curses.KEY_F1, curses.KEY_F13):
                func_key_number = key - curses.KEY_F0
                # If F1 => func_key_number=1, so we pick item index=0
                if 1 <= func_key_number <= len(MENU_OPTIONS_LIST):
                    _, _, func = MENU_OPTIONS_LIST[func_key_number - 1]
                    # call the function directly
                    func(stdscr)

            elif key == curses.KEY_UP:
                selected_idx = (selected_idx - 1) % len(MENU_OPTIONS_LIST)
            elif key == curses.KEY_DOWN:
                selected_idx = (selected_idx + 1) % len(MENU_OPTIONS_LIST)

            # Enter => run the currently highlighted item
            elif key in [curses.KEY_ENTER, 10, 13]:
                _, _, func = MENU_OPTIONS_LIST[selected_idx]
                func(stdscr)

            else:
                # Check single-letter shortcuts
                if 32 <= key < 127:
                    pressed_char = chr(key).upper()
                    found_item = False
                    for i, (m_key, desc, func) in enumerate(MENU_OPTIONS_LIST):
                        if m_key.upper() == pressed_char:
                            func(stdscr)
                            found_item = True
                            break
                    if not found_item:
                        curses.beep()
                else:
                    curses.beep()

    except Exception as e:
        logging.exception("An error occurred in main_menu.")
        curses.endwin()
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
