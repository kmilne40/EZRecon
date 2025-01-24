# google_dork.py
import curses
import logging
import sys
import requests
import re
import json

from utils import display_text  # if you have it, or your spinner, etc.
from api_keys import get_or_prompt_api_key

def google_dork(stdscr):
    """
    Google Dork integrated with curses.
    - Checks for the user's Google API key & CSE ID in api_keys.json
    - If missing, asks once, saves them
    - Reuses them next time without prompting
    """
    try:
        curses.curs_set(0)
        stdscr.clear()

        # 1) Retrieve or prompt for 'google_api_key' and 'google_cse_id'
        #    You can call the "service_name" something like "google" or "google_dork"
        fields = ["api_key", "cse_id"]
        google_keys = get_or_prompt_api_key(stdscr, service_name="google", required_fields=fields)

        api_key = google_keys.get("api_key", "")
        cse_id  = google_keys.get("cse_id", "")

        # If something is still missing, bail out
        if not api_key or not cse_id:
            stdscr.addstr(1, 2, "Google API Key or CSE ID is missing. Please re-run and provide them.")
            stdscr.addstr(3, 2, "Press any key to return...")
            stdscr.refresh()
            stdscr.getch()
            return

        # 2) Now ask user for the domain or queries, etc.
        curses.curs_set(1)
        stdscr.addstr(1, 2, "Enter the domain (e.g., example.com): ")
        curses.echo()
        domain = stdscr.getstr(2, 2, 60).decode().strip()

        stdscr.addstr(4, 2, "Enter the email domain to search (e.g., '@example.com'): ")
        email_query = stdscr.getstr(5, 2, 60).decode().strip()

        stdscr.addstr(7, 2, "Enter technologies (comma separated, e.g., 'WordPress, Apache'): ")
        technology_query = stdscr.getstr(8, 2, 60).decode().strip()
        curses.noecho()
        curses.curs_set(0)
        stdscr.clear()

        # 3) Build search terms
        technologies = [tech.strip() for tech in technology_query.split(',') if tech.strip()]
        search_terms = [
            f"site:{domain} \"email\"",
            f"site:{domain} \"subdomain\"",
            f"site:{domain} \"{email_query}\"",
            f"site:{domain} \"{technology_query}\""
        ]

        # 4) Perform each dork search
        full_output = ""
        for term in search_terms:
            full_output += f"Searching for: {term}\n"
            results = google_search(term, api_key, cse_id, num_results=5)
            full_output += format_results_for_display(results, technologies)
            full_output += "\n"

        # 5) Display the aggregated results (with possible pagination)
        display_text(stdscr, full_output)

        stdscr.addstr(curses.LINES - 2, 2, "Press any key to return...")
        stdscr.refresh()
        stdscr.getch()

    except Exception as e:
        logging.exception("Error in google_dork function.")
        curses.endwin()
        print(f"An error occurred: {e}")
        sys.exit(1)


##############################################################################
# For completeness, here's a minimal version of the helper functions used.
##############################################################################

def google_search(query, api_key, cse_id, num_results=20):
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "q": query,
        "key": api_key,
        "cx": cse_id,
        "num": num_results
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        results = response.json()
        if "items" in results:
            return [
                {
                    "title": item.get("title"),
                    "link": item.get("link"),
                    "snippet": item.get("snippet"),
                }
                for item in results["items"]
            ]
        else:
            return []
    except Exception as err:
        logging.error(f"Google Search error: {err}")
        return []


def format_results_for_display(results, technologies):
    if not results:
        return "No results found.\n"

    lines = []
    for idx, result in enumerate(results, start=1):
        title   = result.get("title", "")
        link    = result.get("link", "")
        snippet = result.get("snippet", "")

        lines.append(f"{idx}. Title: {title}")
        lines.append(f"   Link: {link}")
        lines.append(f"   Snippet: {snippet}")

        # Optional: check for subdomains, emails, tech
        # ...
        lines.append("")  # blank line

    return "\n".join(lines) + "\n"
