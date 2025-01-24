#!/usr/bin/env python3

import curses
import sys
import logging

from menu import main_menu

# =============================================================================
# Logging Configuration
# =============================================================================
logging.basicConfig(
    filename='reccy_toolkit.log',
    level=logging.DEBUG,  # Set to DEBUG for detailed logs
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def main():
    """
    Entry point of the application. Wraps the main_menu with curses.
    """
    try:
        curses.wrapper(main_menu)
    except Exception as e:
        logging.exception("Failed to initialize curses wrapper.")
        print(f"Failed to initialize curses wrapper: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
