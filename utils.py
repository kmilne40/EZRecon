import curses
import sys
import re
import ipaddress
import threading
import time
from tabulate import tabulate

def is_valid_domain(domain):
    domain_regex = re.compile(
        r"^(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
    )
    return bool(domain_regex.match(domain))

def is_valid_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def print_table_custom(data, headers, window, start_y, start_x):
    """
    Prints a table within a curses window at specified coordinates.
    """
    table = tabulate(data, headers=headers, tablefmt="plain")
    lines = table.split('\n')
    for idx, line in enumerate(lines):
        if start_y + idx < curses.LINES - 1:
            try:
                window.addstr(start_y + idx, start_x, line)
            except curses.error:
                pass

class Spinner:
    def __init__(self, stdscr, message="Processing..."):
        self.stdscr = stdscr
        self.message = message
        self.spinner_chars = ['|', '/', '-', '\\']
        self.stop_running = False
        self.thread = threading.Thread(target=self.spin)
        self.current_char = 0

    def spin(self):
        while not self.stop_running:
            try:
                self.stdscr.addstr(
                    curses.LINES - 3, 2,
                    f"{self.message} {self.spinner_chars[self.current_char % len(self.spinner_chars)]}"
                )
                self.stdscr.refresh()
                self.current_char += 1
                time.sleep(0.1)
            except curses.error:
                pass

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_running = True
        self.thread.join()
        # Clear the spinner line after stopping
        try:
            self.stdscr.addstr(curses.LINES - 3, 2, " " * (len(self.message) + 2))
            self.stdscr.refresh()
        except curses.error:
            pass

def display_text(stdscr, text):
    """
    Display multi-line text within the curses window with pagination.
    """
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    lines = text.split('\n')
    max_lines = h - 4  # Reserve lines for header and footer
    for i in range(0, len(lines), max_lines):
        stdscr.clear()
        for idx, line in enumerate(lines[i:i + max_lines], start=1):
            if len(line) > w - 4:
                line = line[:w - 7] + "..."
            try:
                stdscr.addstr(idx, 2, line)
            except curses.error:
                pass
        stdscr.attron(curses.color_pair(3))
        stdscr.addstr(h - 2, 2, "Press SPACE to continue, 'q' to quit...")
        stdscr.attroff(curses.color_pair(3))
        stdscr.refresh()
        while True:
            key = stdscr.getch()
            if key == ord(' '):
                break
            elif key in [ord('q'), ord('Q')]:
                return

def exit_program():
    curses.endwin()
    sys.exit()

def init_colors():
    """
    Initialize color pairs for curses.
    """
    try:
        curses.start_color()
        curses.use_default_colors()
        # Define color pairs
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)    # Selected Option
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)    # Normal Text
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLUE)    # Header
        curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)    # Success
        curses.init_pair(5, curses.COLOR_RED, curses.COLOR_BLACK)      # Error
    except curses.error:
        pass  # Proceed without colors

