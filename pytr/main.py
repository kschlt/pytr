#!/usr/bin/env python

import argparse
import asyncio
import signal
import time

import shtab

from importlib.metadata import version
from pathlib import Path

from pytr.utils import get_logger, check_version, export_transactions
from pytr.dl import DL
from pytr.account import login
from pytr.portfolio import Portfolio
from pytr.alarms import Alarms
from pytr.details import Details


def get_main_parser():
    def formatter(prog):
        return argparse.HelpFormatter(prog, max_help_position=25)

    parser = argparse.ArgumentParser(
        formatter_class=formatter,
        description='Use "%(prog)s command_name --help" to get detailed help to a specific command',
    )
    for grp in parser._action_groups:
        if grp.title == 'options':
            grp.title = 'Options'
        elif grp.title == 'positional arguments':
            grp.title = 'Commands'

    parser.add_argument(
        '-v',
        '--verbosity',
        help='Set verbosity level (default: info)',
        choices=['warning', 'info', 'debug'],
        default='info',
    )
    parser.add_argument('-V', '--version', help='Print version information and quit', action='store_true')
    parser_cmd = parser.add_subparsers(help='Desired action to perform', dest='command')

    # help
    parser_cmd.add_parser('help', help='Print this help message', description='Print help message', add_help=False)

    # Create parent subparser with common login arguments
    parser_login_args = argparse.ArgumentParser(add_help=False)
    parser_login_args.add_argument('--applogin', help='Use app login instead of  web login', action='store_true')
    parser_login_args.add_argument('-n', '--phone_no', help='TradeRepublic phone number (international format)')
    parser_login_args.add_argument('-p', '--pin', help='TradeRepublic pin')

    # login
    info = (
        'Check if credentials file exists. If not create it and ask for input. Try to login.'
        + ' Ask for device reset if needed'
    )
    parser_cmd.add_parser(
        'login',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[parser_login_args],
        help=info,
        description=info,
    )

    # dl_docs
    info = (
        'Download all pdf documents from the timeline and sort them into folders.'
        + ' Also export account transactions (account_transactions.csv)'
        + ' and JSON files with all events (events_with_documents.json and other_events.json'
    )
    parser_dl_docs = parser_cmd.add_parser(
        'dl_docs',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        parents=[parser_login_args],
        help=info,
        description=info,
    )

    parser_dl_docs.add_argument('output', help='Output directory', metavar='PATH', type=Path)
    parser_dl_docs.add_argument(
        '--format',
        help='available variables:\tiso_date, time, title, doc_num, subtitle, id',
        metavar='FORMAT_STRING',
        default='{iso_date}{time} {title}{doc_num}',
    )
    parser_dl_docs.add_argument(
        '--last_days', help='Number of last days to include (use 0 get all days)', metavar='DAYS', default=0, type=int
    )
    parser_dl_docs.add_argument(
        '--workers', help='Number of workers for parallel downloading', metavar='WORKERS', default=8, type=int
    )
    parser_dl_docs.add_argument('--universal', help='Platform independent file names', action='store_true')
    # export_transactions
    info = 'Create a CSV with the deposits and removals ready for importing into Portfolio Performance'
    parser_export_transactions = parser_cmd.add_parser(
        'export_transactions',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help=info,
        description=info,
    )
    parser_export_transactions.add_argument(
        'input', help='Input path to JSON (use other_events.json from dl_docs)', metavar='INPUT', type=Path
    )
    parser_export_transactions.add_argument('output', help='Output path of CSV file', metavar='OUTPUT', type=Path)
    parser_export_transactions.add_argument(
        '-l', '--lang', help='Two letter language code or "auto" for system language', default='auto'
    )

    info = 'Print shell tab completion'
    parser_completion = parser_cmd.add_parser(
        'completion', formatter_class=argparse.ArgumentDefaultsHelpFormatter, help=info, description=info
    )
    shtab.add_argument_to(parser_completion, "shell", parent=parser)
    return parser


def exit_gracefully(signum, frame):
    # restore the original signal handler as otherwise evil things will happen
    # in input when CTRL+C is pressed, and our signal handler is not re-entrant
    global original_sigint
    signal.signal(signal.SIGINT, original_sigint)

    try:
        if input('\nReally quit? (y/n)> ').lower().startswith('y'):
            exit(1)

    except KeyboardInterrupt:
        print('Ok ok, quitting')
        exit(1)

    # restore the exit gracefully handler here
    signal.signal(signal.SIGINT, exit_gracefully)


def main():
    # store the original SIGINT handler
    global original_sigint
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit_gracefully)

    parser = get_main_parser()
    args = parser.parse_args()
    # print(vars(args))

    log = get_logger(__name__, args.verbosity)
    log.setLevel(args.verbosity.upper())
    log.debug('logging is set to debug')

    if args.command == 'login':
        login(phone_no=args.phone_no, pin=args.pin, web=not args.applogin)

    elif args.command == 'dl_docs':
        if args.last_days == 0:
            since_timestamp = 0
        else:
            since_timestamp = (time.time() - (24 * 3600 * args.last_days)) * 1000

        dl = DL(
            login(phone_no=args.phone_no, pin=args.pin, web=not args.applogin),
            args.output,
            args.format,
            since_timestamp=since_timestamp,
            max_workers=args.workers,
            universal_filepath=args.universal,
        )
        asyncio.get_event_loop().run_until_complete(dl.dl_loop())
    elif args.command == 'export_transactions':
        export_transactions(args.input, args.output, args.lang)
    elif args.version:
        installed_version = version('pytr')
        print(installed_version)
        check_version(installed_version)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
