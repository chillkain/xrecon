#!/usr/bin/env python3
# code originally from autorecon but transferred into class format for easier reuse

from colorama import Fore, Style
import sys
import string
from datetime import datetime


class Logger():
    def __init__(self,verbose):
        self.verbose = verbose
        # self.debug("verbosity set to {self.verbose}")

    def set_verbosity(self, verbose):
        self.verbose = verbose
        self.debug("verbosity is set to {self.verbose}")

    def get_verbosity(self):
        return self.verbose

    def cprint(self,*args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, **kvargs):
        frame = sys._getframe(frame_index)

        vals = {
            'bgreen':  Fore.GREEN  + Style.BRIGHT,
            'bred':    Fore.RED    + Style.BRIGHT,
            'bblue':   Fore.BLUE   + Style.BRIGHT,
            'byellow': Fore.YELLOW + Style.BRIGHT,
            'bmagenta': Fore.MAGENTA + Style.BRIGHT,

            'green':  Fore.GREEN,
            'red':    Fore.RED,
            'blue':   Fore.BLUE,
            'yellow': Fore.YELLOW,
            'magenta': Fore.MAGENTA,

            'bright': Style.BRIGHT,
            'srst':   Style.NORMAL,
            'crst':   Fore.RESET,
            'rst':    Style.NORMAL + Fore.RESET
        }

        vals.update(frame.f_globals)
        vals.update(frame.f_locals)
        vals.update(kvargs)
        unfmt = ''
        if char is not None:
            time = datetime.now()
            now = time.strftime("%d.%m.%Y-%H:%M:%S")
            unfmt += f"[{now}]" + color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET + sep
        unfmt += sep.join(args)

        fmted = unfmt

        for attempt in range(10):
            try:
                fmted = string.Formatter().vformat(unfmt, args, vals)
                break
            except KeyError as err:
                key = err.args[0]
                unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

        print(fmted, sep=sep, end=end, file=file)

    def debug(self,*args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout, **kvargs):
        if self.verbose >= 2:
            self.cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def info(self,*args, sep=' ', end='\n', file=sys.stdout, **kvargs):
        self.cprint(*args, color=Fore.GREEN, char='*', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def warn(self,*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
        self.cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def error(self,*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
        self.cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def fail(self,*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
        self.cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)
        exit(-1)

if __name__ == "__main__":
    verbose=0
    tag = 'nmap_function_yo'
    address= '1.1.1.1'
    command= 'echo test'

    logger = Logger(verbose)
    logger.debug('Running service detection {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}' if logger.get_verbosity() >= 1 else ''))
    logger.info('Running service detection {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}' if logger.get_verbosity() >= 1 else ''))
    logger.warn('Running service detection {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}' if logger.get_verbosity() >= 1 else ''))
    logger.error('Running service detection {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}' if logger.get_verbosity() >= 1 else ''))
    logger.fail('Running service detection {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}' if logger.get_verbosity() >= 1 else ''))






