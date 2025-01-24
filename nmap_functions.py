# nmap_functions.py

import curses
import sys
import logging
import subprocess

from utils import Spinner, display_text  # Adjust if needed

def nmap_lookup_submenu(stdscr):
    """
    A sub-menu for Nmap functionalities:
      1) Basic Host Discovery
      2) Port Scan
      3) NSE Scripts (sub-menu)
      X) Return to Main
    """
    try:
        nmap_menu = [
            ("1", "Basic Host Discovery"),
            ("2", "Port Scan"),
            ("3", "NSE Scripts"),
            ("X", "Return to Main Menu")
        ]

        selected_idx = 0

        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            stdscr.border(0)

            header = "===== NMAP SUB-MENU ====="
            stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(1, width // 2 - len(header) // 2, header)
            stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

            menu_title = "Nmap Options"
            stdscr.attron(curses.color_pair(2) | curses.A_UNDERLINE)
            stdscr.addstr(3, 2, menu_title)
            stdscr.attroff(curses.color_pair(2) | curses.A_UNDERLINE)

            for idx, (key, desc) in enumerate(nmap_menu):
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

            footer = "Use Arrow Keys to Navigate, Enter to Select, 'X' to Return"
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(height - 2, width // 2 - len(footer) // 2, footer)
            stdscr.attroff(curses.color_pair(3))

            stdscr.refresh()
            key = stdscr.getch()

            if key in [ord('x'), ord('X')]:
                return

            elif key in [curses.KEY_ENTER, 10, 13]:
                chosen_key = nmap_menu[selected_idx][0]
                if chosen_key == '1':
                    nmap_host_discovery(stdscr)
                elif chosen_key == '2':
                    nmap_port_scan(stdscr)
                elif chosen_key == '3':
                    nmap_nse_submenu(stdscr)
                else:
                    return

            elif key == curses.KEY_UP:
                selected_idx = (selected_idx - 1) % len(nmap_menu)
            elif key == curses.KEY_DOWN:
                selected_idx = (selected_idx + 1) % len(nmap_menu)
            else:
                # direct shortcuts (1,2,3,x)
                if 32 <= key < 127:
                    pressed_char = chr(key)
                    found = False
                    for i, (m_key, desc) in enumerate(nmap_menu):
                        if m_key == pressed_char:
                            found = True
                            if pressed_char == '1':
                                nmap_host_discovery(stdscr)
                            elif pressed_char == '2':
                                nmap_port_scan(stdscr)
                            elif pressed_char == '3':
                                nmap_nse_submenu(stdscr)
                            else:
                                return
                            break
                    if not found:
                        curses.beep()
                else:
                    curses.beep()

    except Exception as e:
        logging.exception("Error in nmap_lookup_submenu.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)


def nmap_host_discovery(stdscr):
    """
    Prompts user for a network range or domain, 
    runs nmap -sn (host discovery), and displays results.
    """
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter target (IP, range, or domain) for host discovery: ")
        curses.echo()
        target = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not target:
            stdscr.addstr(1, 2, "No target specified. Press any key to return...")
            stdscr.getch()
            return

        command = ["nmap", "-sn", target]

        spinner = Spinner(stdscr, f"Running: {' '.join(command)}")
        spinner.start()

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        spinner.stop()

        output = f"Command: {' '.join(command)}\n\n"
        if result.returncode == 0:
            output += result.stdout
        else:
            output += f"Error: {result.stderr}"

        display_text(stdscr, output)
        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the Nmap menu...")
        stdscr.refresh()
        stdscr.getch()

    except Exception as e:
        logging.exception("Error in nmap_host_discovery.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)


def nmap_port_scan(stdscr):
    """
    Prompts for target and port(s), runs a basic Nmap scan.
    """
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter target (IP, domain, or range): ")
        curses.echo()
        target = stdscr.getstr(2, 2, 60).decode().strip()

        stdscr.addstr(4, 2, "Enter comma-separated ports (e.g. 80,443): ")
        ports_str = stdscr.getstr(5, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not target:
            stdscr.addstr(1, 2, "No target specified. Press any key to return...")
            stdscr.getch()
            return

        command = ["nmap", "-p", ports_str, target]

        spinner = Spinner(stdscr, f"Running: {' '.join(command)}")
        spinner.start()

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        spinner.stop()

        output = f"Command: {' '.join(command)}\n\n"
        if result.returncode == 0:
            output += result.stdout
        else:
            output += f"Error: {result.stderr}"

        display_text(stdscr, output)
        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the Nmap menu...")
        stdscr.refresh()
        stdscr.getch()
        curses.curs_set(0)

    except Exception as e:
        logging.exception("Error in nmap_port_scan.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)


def nmap_nse_submenu(stdscr):
    """
    Sub-menu for Nmap NSE scripts.
    Let's list some known, commonly used scripts for easy selection.
    """
    try:
        # A sample dictionary of script name -> short description
        nse_scripts = {
            "ftp-anon": "Check anonymous FTP login",
            "http-enum": "Enumerate folders/files via HTTP",
            "smb-enum-shares": "List SMB shares",
            "ssl-cert": "Retrieve SSL certificate",
            "vulners": "Check for vulnerabilities"
        }

        # Convert to a list for easy iteration
        script_items = list(nse_scripts.items())  # [(script, desc), ...]

        # We'll build a small menu out of these scripts
        script_menu = [(str(i+1), f"{scr} - {desc}") for i, (scr, desc) in enumerate(script_items)]
        # Add an option to return
        script_menu.append(("X", "Return to Nmap Menu"))

        selected_idx = 0

        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            stdscr.border(0)

            header = "===== NMAP NSE SCRIPTS ====="
            stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(1, width // 2 - len(header) // 2, header)
            stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

            menu_title = "Common NSE Scripts"
            stdscr.attron(curses.color_pair(2) | curses.A_UNDERLINE)
            stdscr.addstr(3, 2, menu_title)
            stdscr.attroff(curses.color_pair(2) | curses.A_UNDERLINE)

            for idx_i, (key, desc) in enumerate(script_menu):
                x = 4
                y = 5 + idx_i
                if idx_i == selected_idx:
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
                chosen = script_menu[selected_idx][0]
                if chosen.upper() == 'X':
                    return
                else:
                    # The user selected a script
                    script_index = int(chosen) - 1
                    script_name = script_items[script_index][0]
                    run_nmap_nse_script(stdscr, script_name)
            elif key == curses.KEY_UP:
                selected_idx = (selected_idx - 1) % len(script_menu)
            elif key == curses.KEY_DOWN:
                selected_idx = (selected_idx + 1) % len(script_menu)
            else:
                if 32 <= key < 127:
                    pressed_char = chr(key)
                    if pressed_char.upper() == 'X':
                        return
                    elif pressed_char.isdigit():
                        idx_int = int(pressed_char) - 1
                        if 0 <= idx_int < len(script_items):
                            script_name = script_items[idx_int][0]
                            run_nmap_nse_script(stdscr, script_name)
                        else:
                            curses.beep()
                    else:
                        curses.beep()
                else:
                    curses.beep()

    except Exception as e:
        logging.exception("Error in nmap_nse_submenu.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)


def run_nmap_nse_script(stdscr, script_name):
    """
    Asks the user for a target, then runs Nmap with the chosen NSE script.
    e.g. nmap --script=ftp-anon -p 21 <target>
    """
    try:
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, f"Selected script: {script_name}")
        stdscr.addstr(3, 2, "Enter target (IP, domain, etc.): ")
        curses.echo()
        target = stdscr.getstr(4, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not target:
            stdscr.addstr(1, 2, "No target entered. Returning...")
            stdscr.getch()
            return

        # If a known port is associated with the script (like ftp-anon => port 21),
        # we can auto-suggest. But let's just ask user for ports:
        stdscr.addstr(1, 2, "Enter ports to scan or leave blank (e.g. 21,80,443): ")
        curses.echo()
        ports = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        command = ["nmap", "--script", script_name]
        if ports:
            command += ["-p", ports]
        command.append(target)

        spinner = Spinner(stdscr, f"Running: {' '.join(command)}")
        spinner.start()

        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        spinner.stop()

        output = f"Command: {' '.join(command)}\n\n"
        if result.returncode == 0:
            output += result.stdout
        else:
            output += f"Error: {result.stderr}"

        display_text(stdscr, output)
        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the NSE menu...")
        stdscr.refresh()
        stdscr.getch()
        curses.curs_set(0)

    except Exception as e:
        logging.exception("Error in run_nmap_nse_script.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)
