# shodan_functions.py

import curses
import sys
import logging
import shodan
from tabulate import tabulate

# Your local imports
from utils import (
    is_valid_ip,
    Spinner,
    display_text
)
from api_keys import get_or_prompt_api_key

api = None  # We'll set this once we load from the keys file.

def init_shodan_api(stdscr):
    """
    Ensures the global 'api' is initialized with your Shodan API key from api_keys.json.
    Prompts once if the key is missing.
    """
    global api
    if api is not None:
        return  # already loaded

    # Retrieve "shodan" credentials from api_keys.json
    keys = get_or_prompt_api_key(stdscr, service_name="shodan", required_fields=["api_key"])
    shodan_key = keys.get("api_key", "")

    if shodan_key:
        try:
            api = shodan.Shodan(shodan_key)
            logging.debug("Shodan API initialized successfully from api_keys.json.")
        except Exception as e:
            logging.error(f"Error initializing Shodan API: {e}")
    else:
        logging.error("No Shodan API key provided. Shodan features will fail.")


def shodan_lookup_submenu(stdscr):
    """
    Displays a sub-menu for Shodan functionalities:
      1) Shodan Search
      2) Shodan Host Information
      3) Shodan Query Help
      4) TCP-Port List
      X) Return to Main Menu
    """
    try:
        # First, make sure we have the Shodan key loaded:
        init_shodan_api(stdscr)

        # If still no 'api', the user never provided a key
        if not api:
            curses.curs_set(1)
            stdscr.clear()
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, "Shodan API is not initialized. Please check your API key.")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            curses.curs_set(0)
            return

        shodan_menu = [
            ("1", "Shodan Search"),
            ("2", "Shodan Host Information"),
            ("3", "Shodan Query Help"),
            ("4", "TCP-Port List"),
            ("X", "Return to Main Menu")
        ]

        selected_idx = 0

        while True:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            stdscr.border(0)

            header = "===== SHODAN LOOKUP SUB-MENU ====="
            stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(1, width // 2 - len(header) // 2, header)
            stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

            menu_title = "Shodan Options"
            stdscr.attron(curses.color_pair(2) | curses.A_UNDERLINE)
            stdscr.addstr(3, 2, menu_title)
            stdscr.attroff(curses.color_pair(2) | curses.A_UNDERLINE)

            for idx, (key, desc) in enumerate(shodan_menu):
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
                chosen_key = shodan_menu[selected_idx][0]
                if chosen_key == '1':
                    shodan_search(stdscr)
                elif chosen_key == '2':
                    shodan_host_info(stdscr)
                elif chosen_key == '3':
                    shodan_query_help(stdscr)
                elif chosen_key == '4':
                    tcp_port_list(stdscr)
                else:
                    return

            elif key == curses.KEY_UP:
                selected_idx = (selected_idx - 1) % len(shodan_menu)
            elif key == curses.KEY_DOWN:
                selected_idx = (selected_idx + 1) % len(shodan_menu)
            else:
                if 32 <= key < 127:
                    pressed_char = chr(key)
                    found = False
                    for i, (m_key, desc) in enumerate(shodan_menu):
                        if m_key == pressed_char:
                            found = True
                            if pressed_char == '1':
                                shodan_search(stdscr)
                            elif pressed_char == '2':
                                shodan_host_info(stdscr)
                            elif pressed_char == '3':
                                shodan_query_help(stdscr)
                            elif pressed_char == '4':
                                tcp_port_list(stdscr)
                            else:
                                return
                            break
                    if not found:
                        curses.beep()
                else:
                    curses.beep()

    except Exception as e:
        logging.exception("Error in shodan_lookup_submenu function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)


def shodan_search(stdscr):
    """
    Shodan Search logic. Uses the global 'api' after init_shodan_api().
    """
    try:
        from utils import Spinner
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter Shodan search query (e.g., apache port:80): ")
        curses.echo()
        query = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        if not query:
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, "No search query entered.")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        stdscr.addstr(1, 2, f"[*] Performing Shodan search for: {query}\n")
        stdscr.refresh()

        spinner = Spinner(stdscr, "Searching Shodan")
        spinner.start()

        import shodan
        global api
        try:
            results = api.search(query)
            spinner.stop()
            output = f"Shodan Search Results for '{query}':\n\n"

            if 'matches' in results and results['matches']:
                from tabulate import tabulate
                table_data = []
                for idx, match in enumerate(results['matches'], start=1):
                    if idx > 100:
                        output += "More results available... Only displaying first 100.\n"
                        break
                    ip_str = match.get('ip_str', 'N/A')
                    port = match.get('port', 'N/A')
                    data = match.get('data', '').replace('\n', ' ').strip()
                    if len(data) > 50:
                        data = data[:47] + "..."
                    table_data.append((idx, ip_str, port, data))

                if table_data:
                    table = tabulate(table_data, headers=["#", "IP", "Port", "Data"], tablefmt="plain")
                    output += table
                else:
                    output += "No results found."
            else:
                output += "No results found."

            from utils import display_text
            display_text(stdscr, output)

        except shodan.APIError as e:
            spinner.stop()
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(3, 2, f"Shodan API error: {e}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the menu...")
            stdscr.getch()

        curses.curs_set(0)

    except Exception as e:
        logging.exception("Error in shodan_search function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)


def shodan_host_info(stdscr):
    """
    Shodan Host Info logic. Uses global 'api' after init_shodan_api().
    """
    try:
        from utils import Spinner
        curses.curs_set(1)
        stdscr.clear()
        stdscr.addstr(1, 2, "Enter IP address for Shodan Host Information: ")
        curses.echo()
        ip_address = stdscr.getstr(2, 2, 60).decode().strip()
        curses.noecho()
        stdscr.clear()

        from utils import is_valid_ip
        if not is_valid_ip(ip_address):
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(1, 2, f"Invalid IP address: {ip_address}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(3, 2, "Press any key to return to the menu...")
            stdscr.getch()
            return

        stdscr.addstr(1, 2, f"[*] Retrieving Shodan host information for: {ip_address}\n")
        stdscr.refresh()

        spinner = Spinner(stdscr, "Fetching host info from Shodan")
        spinner.start()

        import shodan
        global api
        try:
            host = api.host(ip_address)
            spinner.stop()

            output = f"Shodan Host Information for {ip_address}:\n\n"
            output += f"IP: {host.get('ip_str', 'N/A')}\n"
            output += f"Organization: {host.get('org', 'N/A')}\n"
            output += f"Operating System: {host.get('os', 'N/A')}\n\n"

            # Ports/Services
            output += "Open Ports and Services:\n"
            from tabulate import tabulate
            port_service_data = []
            for service in host.get('data', []):
                port = service.get('port', 'N/A')
                service_name = service.get('product', 'N/A')
                banner = service.get('data', '').replace('\n', ' ').strip()
                if len(banner) > 50:
                    banner = banner[:47] + "..."
                port_service_data.append((port, service_name, banner))

            if port_service_data:
                table = tabulate(port_service_data, headers=["Port", "Service", "Banner"], tablefmt="plain")
                output += table + "\n\n"
            else:
                output += "No open ports/services info.\n\n"

            # Vulnerabilities
            vulns = host.get('vulns', [])
            if vulns:
                output += "Vulnerabilities:\n"
                for v in vulns:
                    output += f"- {v}\n"
                output += "\n"
            else:
                output += "No vulnerabilities info.\n\n"

            # DNS
            dns_info = host.get('dns', {})
            if dns_info:
                output += "DNS Information:\n"
                for key, value in dns_info.items():
                    val_str = str(value)
                    if len(val_str) > 100:
                        val_str = val_str[:97] + "..."
                    output += f"{key}: {val_str}\n"
                output += "\n"
            else:
                output += "No DNS information.\n\n"

            # HTTP
            http_info = host.get('http', {})
            if http_info:
                output += "HTTP Information:\n"
                for key, value in http_info.items():
                    val_str = str(value)
                    if len(val_str) > 100:
                        val_str = val_str[:97] + "..."
                    output += f"{key}: {val_str}\n"
                output += "\n"
            else:
                output += "No HTTP information.\n\n"

            # Additional
            additional_info = host.get('data', [])
            if additional_info:
                output += "Additional Service Information:\n"
                for service in additional_info:
                    banner = service.get('data', '').replace('\n', ' ').strip()
                    if len(banner) > 100:
                        banner = banner[:97] + "..."
                    output += f"- Port {service.get('port', 'N/A')}: {banner}\n"
                output += "\n"
            else:
                output += "No additional service information.\n\n"

            from utils import display_text
            display_text(stdscr, output)

        except shodan.APIError as e:
            spinner.stop()
            stdscr.attron(curses.color_pair(5))
            stdscr.addstr(3, 2, f"Shodan API error: {e}")
            stdscr.attroff(curses.color_pair(5))
            stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to the menu...")
            stdscr.getch()

        curses.curs_set(0)

    except Exception as e:
        logging.exception("Error in shodan_host_info function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)


def shodan_query_help(stdscr):
    """
    Option 3: Shodan Query cheat sheet
    """
    try:
        curses.curs_set(0)
        stdscr.clear()

        help_text = """\
================== SHODAN QUERY HELP ==================

Below are some free-form query examples to help you out!

1) Domain-based queries
   - "hostname:example.com" (e.g., "apache hostname:example.com")
   - Or "ssl:example.com" to look for SSL cert references.

2) Organization-based queries
   - org:"Your Organization" to filter results to a specific org.
   - Combine with ports, e.g. org:"Google" port:443

3) Network queries
   - net:192.168.0.0/24 to search within a CIDR range.

4) Ports
   - port:80 or port:443 or any other port
   - Combine with org, net, or other filters.

5) Free-form
   - Shodan supports advanced boolean logic:
     title:"RouterOS" OR product:"MikroTik"
     country:"US" city:"New York" port:21

6) Combining everything
   - e.g., org:"Microsoft" net:13.64.0.0/11 port:3389
   - e.g., ssl.cert.issuer.CN:"Let's Encrypt" hostname:example.com

Simplest ones are:

 - hostname:example.com
 - org:"Your Org" port:443
 - net:192.168.0.0/24
 - ssl.cert.issuer.CN:"Let's Encrypt"
 - Apache port:80

"""

        from utils import display_text
        display_text(stdscr, help_text)
        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to Shodan sub-menu...")
        stdscr.refresh()
        stdscr.getch()

    except Exception as e:
        logging.exception("Error in shodan_query_help function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)


def tcp_port_list(stdscr):
    """
    Option 4: TCP-Port List
    """
    try:
        curses.curs_set(0)
        stdscr.clear()

        ports_info = [
            (80, "HTTP - Used by web servers"),
    (443, "HTTPS - Secure web traffic"),
    (22, "SSH - Secure Shell for remote login"),
    (21, "FTP - File Transfer Protocol"),
    (23, "Telnet - Unsecured remote login"),
    (25, "SMTP - Simple Mail Transfer Protocol"),
    (110, "POP3 - Post Office Protocol for email retrieval"),
    (143, "IMAP - Internet Message Access Protocol"),
    (53, "DNS - Domain Name System"),
    (3306, "MySQL - MySQL database service"),
    (3389, "RDP - Remote Desktop Protocol"),
    (445, "SMB - Server Message Block file sharing"),
    (139, "NetBIOS - Network Basic Input/Output System"),
    (161, "SNMP - Simple Network Management Protocol"),
    (162, "SNMPTRAP - SNMP Trap messages"),
    (389, "LDAP - Lightweight Directory Access Protocol"),
    (636, "LDAPS - Secure LDAP"),
    (8080, "HTTP Proxy - Alternative web server port"),
    (135, "MSRPC - Microsoft Remote Procedure Call"),
    (514, "Syslog - System logging service"),
    (993, "IMAPS - Secure IMAP"),
    (995, "POP3S - Secure POP3"),
    (1723, "PPTP - Point-to-Point Tunneling Protocol"),
    (69, "TFTP - Trivial File Transfer Protocol"),
    (2049, "NFS - Network File System"),
    (5900, "VNC - Virtual Network Computing"),
    (5060, "SIP - Session Initiation Protocol"),
    (5061, "SIPS - Secure Session Initiation Protocol"),
    (500, "ISAKMP - Internet Security Association Key Management Protocol"),
    (4500, "IPSec NAT-T - IPSec NAT traversal"),
    (67, "DHCP - Dynamic Host Configuration Protocol (Server)"),
    (68, "DHCP - Dynamic Host Configuration Protocol (Client)"),
    (123, "NTP - Network Time Protocol"),
    (1812, "RADIUS - Authentication service"),
    (1813, "RADIUS Accounting - Accounting service"),
    (512, "Exec - Remote command execution"),
    (513, "Rlogin - Remote login"),
    (8000, "Common alternative for HTTP"),
    (8443, "Common alternative for HTTPS"),
    (3000, "Development HTTP server"),
    (6000, "X11 - X Window System"),
    (32768, "Windows RPC - Ephemeral ports"),
    (9100, "JetDirect - Printing service"),
    (1433, "MSSQL - Microsoft SQL Server"),
    (1434, "MSSQL Monitor - Microsoft SQL Server Monitor"),
    (10000, "Webmin - Web-based server management"),
    (24800, "Synergy - Input sharing software"),
    (11211, "Memcached - Memory object caching system"),
    (5000, "Flask/Django - Python development servers"),
    (1883, "MQTT - Message Queuing Telemetry Transport"),
    (8883, "MQTT Secure - Secure MQTT"),
    (6379, "Redis - Key-value store"),
    (27017, "MongoDB - Database service"),
    (5432, "PostgreSQL - Database service"),
    (1521, "Oracle DB - Oracle database listener"),
    (9200, "Elasticsearch - Search engine"),
    (9300, "Elasticsearch Cluster Communication"),
    (27015, "Source Engine - Game servers"),
    (7547, "CWMP - CPE WAN Management Protocol"),
    (10050, "Zabbix - Monitoring agent"),
    (10051, "Zabbix - Monitoring server"),
    (6667, "IRC - Internet Relay Chat"),
    (2000, "Cisco SCCP - Skinny Call Control Protocol"),
    (4000, "Diablo II - Game Servers"),
    (8181, "HTTP Proxy - Alternative HTTP"),
    (9090, "Openfire - Messaging Server"),
    (5500, "VNC - Remote Access"),
    (3270, "TN3270 - Telnet for IBM mainframes"),
            (21,   "FTP"),
            (22,   "SSH"),
            (25,   "SMTP"),
            (53,   "DNS"),
            (80,   "HTTP"),
            (110,  "POP3"),
            (143,  "IMAP"),
            (443,  "HTTPS"),
            (3306, "MySQL"),
            (3389, "RDP"),
            (1521, "Oracle SQL"),
        ]

        lines = ["========== TCP-Port List ==========\n"]
        for port, protocol in ports_info:
            lines.append(f"Port Number: {port}  Protocol Name: {protocol}")
        lines.append("")
        output_text = "\n".join(lines)

        from utils import display_text
        display_text(stdscr, output_text)
        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return to Shodan sub-menu...")
        stdscr.refresh()
        stdscr.getch()

    except Exception as e:
        logging.exception("Error in tcp_port_list function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)
