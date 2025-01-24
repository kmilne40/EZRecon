# hydra_functions.py

import curses
import sys
import logging
import subprocess
from utils import Spinner, display_text

def hydra_lookup_submenu(stdscr):
    """
    Sub-menu for Hydra usage, adapted to your Reccy style:
      1) Basic Hydra Attack (Now also asks for port)
      2) Common Protocol Examples
      X) Return to Main Menu
    """
    try:
        hydra_menu = [
            ("1", "Basic Hydra Attack"),
            ("2", "Common Protocol Examples"),
            ("X", "Return to Main Menu")
        ]

        selected_idx = 0

        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            stdscr.border(0)

            header = "===== HYDRA SUB-MENU ====="
            stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(1, width // 2 - len(header) // 2, header)
            stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

            menu_title = "Hydra Options"
            stdscr.attron(curses.color_pair(2) | curses.A_UNDERLINE)
            stdscr.addstr(3, 2, menu_title)
            stdscr.attroff(curses.color_pair(2) | curses.A_UNDERLINE)

            for idx, (key, desc) in enumerate(hydra_menu):
                x = 4
                y = 5 + idx
                if idx == selected_idx:
                    stdscr.attron(curses.color_pair(1))
                    stdscr.addstr(y, x, f"> {key}: {desc}")
                    stdscr.attroff(curses.color_pair(1))
                else:
                    if key.upper() == 'X':
                        stdscr.attron(curses.color_pair(5))
                        stdscr.addstr(y, x, f"  {key}: {desc}")
                        stdscr.attroff(curses.color_pair(5))
                    else:
                        stdscr.attron(curses.color_pair(2))
                        stdscr.addstr(y, x, f"  {key}: {desc}")
                        stdscr.attroff(curses.color_pair(2))

            footer = "Use Arrow Keys, Enter to Select, 'X' to Return"
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(height - 2, width // 2 - len(footer) // 2, footer)
            stdscr.attroff(curses.color_pair(3))

            stdscr.refresh()
            key = stdscr.getch()

            if key in [ord('x'), ord('X')]:
                return

            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_key = hydra_menu[selected_idx][0]
                if chosen_key == '1':
                    hydra_basic_attack(stdscr)
                elif chosen_key == '2':
                    hydra_protocol_examples(stdscr)
                else:
                    return

            elif key == curses.KEY_UP:
                selected_idx = (selected_idx - 1) % len(hydra_menu)
            elif key == curses.KEY_DOWN:
                selected_idx = (selected_idx + 1) % len(hydra_menu)
            else:
                if 32 <= key < 127:
                    pressed_char = chr(key)
                    found = False
                    for i, (m_key, desc) in enumerate(hydra_menu):
                        if m_key == pressed_char:
                            found = True
                            if pressed_char == '1':
                                hydra_basic_attack(stdscr)
                            elif pressed_char == '2':
                                hydra_protocol_examples(stdscr)
                            else:
                                return
                            break
                    if not found:
                        curses.beep()
                else:
                    curses.beep()

    except Exception as e:
        logging.exception("Error in hydra_lookup_submenu.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

def hydra_basic_attack(stdscr):
    """
    Prompts for target, service, port, userlist, passlist, runs Hydra.
    Logs that Hydra is being called.
    """
    try:
        curses.curs_set(1)
        stdscr.clear()

        stdscr.addstr(1, 2, "Enter target IP or domain: ")
        curses.echo()
        target = stdscr.getstr(2, 2, 60).decode().strip()

        stdscr.addstr(4, 2, "Enter service/protocol (e.g., ftp, ssh, http-form-post): ")
        service = stdscr.getstr(5, 2, 60).decode().strip()

        stdscr.addstr(7, 2, "Enter port (leave blank to default for that protocol): ")
        port_str = stdscr.getstr(8, 2, 60).decode().strip()

        stdscr.addstr(10, 2, "Path to user list (e.g., /usr/share/wordlists/users.txt): ")
        user_list = stdscr.getstr(11, 2, 60).decode().strip()

        stdscr.addstr(13, 2, "Path to password list: ")
        pass_list = stdscr.getstr(14, 2, 60).decode().strip()

        curses.noecho()
        stdscr.clear()

        if not target or not service:
            stdscr.addstr(1, 2, "Missing required fields. Press any key to return...")
            stdscr.refresh()
            stdscr.getch()
            return

        # Build hydra command
        command = ["hydra"]
        if user_list:
            command += ["-L", user_list]
        if pass_list:
            command += ["-P", pass_list]
        if port_str:
            # Hydra uses -s <port> for specifying port
            command += ["-s", port_str]
        command += ["-f", "-v", "-o", "hydra_results.txt", f"{service}://{target}"]

        logging.info(f"Calling Hydra with command: {' '.join(command)}")  # LOG

        spinner = Spinner(stdscr, f"Running: {' '.join(command)}")
        spinner.start()

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        spinner.stop()

        output = f"Command: {' '.join(command)}\n\n"
        # Hydra returns 255 if no success found; that is not necessarily an error
        if result.returncode in [0, 255]:
            output += result.stdout
        else:
            output += f"Error: {result.stderr}"

        from utils import display_text
        display_text(stdscr, output)

        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the Hydra menu...")
        stdscr.refresh()
        stdscr.getch()
        curses.curs_set(0)

    except Exception as e:
        logging.exception("Error in hydra_basic_attack.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)

def hydra_protocol_examples(stdscr):
    """
    Shows some common Hydra usage examples for various protocols.
    """
    try:
        curses.curs_set(0)
        stdscr.clear()

        examples_text = """\
HYDRA COMMON PROTOCOL EXAMPLES

1) FTP:
   hydra -l admin -P passwords.txt ftp://192.168.1.10

2) SSH:
   hydra -l root -P pass.txt ssh://192.168.1.20

3) HTTP Form:
   hydra -l admin -P pass.txt 192.168.1.30 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

4) SMB:
   hydra -L users.txt -P pass.txt smb://192.168.1.40

Output is typically shown on screen and saved to hydra_results.txt if you add -o param.
"""

        display_text(stdscr, examples_text)
        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the Hydra menu...")
        stdscr.refresh()
        stdscr.getch()

    except Exception as e:
        logging.exception("Error in hydra_protocol_examples.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)
