# from ports import ports_1000_str as PORTS_1000
from exc import IPAddressInvalid, FileAlreadyExists, ScanNotFoundError

import time
import os
import sys
# from bs4 import BeautifulSoup
import subprocess
from pathlib import Path
import nmap
import ipaddress
from pyfiglet import Figlet
import click

from rich import box, print as rprint
# from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.pretty import pprint
from rich.progress import track
from rich.progress import Progress


# TODO: make ffuf fuzzing process happen in a new thread, so the Nmap scan can 
# continue uninterrupted? 
# Another solution is make an empty list, append port #s running http to list
# and then iterate through the list after the nmap scan is done. 
# Yeah, that sounds simpler.
# -----------------------------------------------------------------------------

console = Console()


def banner():
    """Creates the banner lol"""
    f = Figlet(font='slant')
    return f.renderText('CTF Time')


class CTFStarter(nmap.PortScanner):
    
    def __init__(self, target_ip, dir_name, *args, **kwargs):

        super().__init__(*args, **kwargs)
        self.TARGET_IP      = target_ip
        self.HOME           = Path().home()
        self.DIR_NAME       = dir_name
        self.DIR_PATH       = f"{self.HOME}/ctf/thm/{self.DIR_NAME}"
        self.SCANS          = f"{self.DIR_PATH}/scans"
        self.WORDLIST       = '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt'
        self.ports          = []
        self.open_ports     = []
        self.web_ports      = []
        self.scan_results   = None



    def make_dirs(self):
        """Create the directory and notes file for the CTF."""
        try:
            os.makedirs(self.SCANS, exist_ok=False)
            os.mknod(f"{self.DIR_PATH}/notes")
        except FileExistsError:
            raise FileAlreadyExists
        except OSError:
            raise FileAlreadyExists
        return


    def validate_ip(self):
        """Checks if user-supplied IP address is legit."""
        try:
            ip = ipaddress.ip_address(self.TARGET_IP)
        except ValueError:
            raise IPAddressInvalid 
        else:
            return ip


    def scan_target(self):
        """Nmap scan of target IP. Records the results to self.scan_results 
        and also self.open_ports"""
        rprint('[SCANNING] Starting Nmap Scan...')
        arguments = f"-sV -vv -oN {self.SCANS}/sV"

        with Progress(transient=True) as progress:
            print()
            for i in range(0,1):
                task = progress.add_task("[cyan]Scanning...", total=None)
                self.scan(
                    hosts = self.TARGET_IP, 
                    # ports = '21,22,80,139', 
                    arguments = arguments,
                    # sudo = True
                )
        for host in self.all_hosts():
            rprint(f"[HOST] {host}")
        rprint(f"[ARGS] {self.command_line()}")
        try:
            self._record_scan_results()
        except ScanNotFoundError as e:
            rprint(e.message)
            exit(0)
        self._ports_list()

        return


    def _record_scan_results(self):
        """Records scan results to self.ports 
        and self.scan_results attributes
        """
        try:
            self.scan_results = self[self.TARGET_IP]
        except KeyError:
            raise ScanNotFoundError

        return


    def _ports_list(self):
        """Make an iterable list of the open ports. 
        Makes it easier to perform operations on them later.
        """
        ports = []
        open_ports = []
        for protocol in self.scan_results.all_protocols():
            for port, value in self.scan_results[protocol].items():
                d = value
                d['port'] = port
                ports.append(d)
                if value['state'] == 'open':
                    open_ports.append(d)
        self.ports = ports
        self.open_ports = open_ports

        return


    def start_fuzzing(self):
        """Iterates through the open http ports and fuzzes them. lol"""
        with Progress(transient=True) as progress:
            for port in self.web_ports:
                task = progress.add_task("[cyan]Fuzzing...", total=None)
                self._run_ffuf(port['port'])

        return


    def check_webservers(self):
        """Parse the results of the Nmap scan and display 
        on the command line which ports are open.
        If any http servers are running, begin fuzzing with FFUF
        """
        web_ports = []
        for port in self.open_ports:
            if port['name'] == 'http' and port['state'] == 'open' and port['port'] != 443:
                web_ports.append(port)
        self.web_ports = web_ports

        return


    def print_nmap_results(self):
        """Prints out the Nmap scan results."""
        result = subprocess.run(
            ['cat', f"{self.SCANS}/sV"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        result_text = result.stdout.decode('utf-8')
        print()
        print()
        rprint(result_text)
        print()
        print()

        return


    def _run_ffuf(self, port: int):
        """Runs FFUF with a default wordlist on any webserver ports and saves the output to a file in scans."""
        rprint('==============================')
        rprint(f"[bold]Fuzzing on port:\t{port}")
        rprint('==============================')
        url = f"http://{self.TARGET_IP}:{port}"

        result = subprocess.run(
            ['ffuf', '-u', f"{url}/FUZZ", '-w', f"{self.WORDLIST}"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE
        )
        result_text = result.stdout.decode('utf-8')
        print(result_text)
        print()
        fd = os.open(f"{self.SCANS}/ffuf_results", os.O_WRONLY| os.O_CREAT, mode=0o644)
        os.write(fd, result.stdout)
        
        return


    def searchsploit(self):
        """Checks searchsploit for known vulnerabilities"""
        for port in self.open_ports:
            rprint(f"[bold]Port {port['port']} - {port['name']}")
            result = subprocess.run(
                ['searchsploit', f"{port['product']}", f"{port['version']}"], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            result_text = result.stdout.decode('utf-8')
            print(result_text)
            print()
        
        return


@click.command()
@click.argument('ip')
@click.argument('name')
# @click.option('--ip', help='The IP Address to scan.')
# @click.option('--name', help='The name of the CTF')
def main(ip, name):

    print()
    banner_text = banner().rstrip() + '\n'
    rprint(Panel(banner_text, subtitle='Version 1.0', expand=False, box=box.DOUBLE))
    print()

    ctf = CTFStarter(ip, name)
    
    try:
        ctf.make_dirs()
    except FileAlreadyExists as e:
        rprint(e.message)
        exit(0)
    try: 
        ctf.validate_ip()
    except IPAddressInvalid as e:
        rprint(e.message)
        exit(0)
    ctf.scan_target()
    ctf.print_nmap_results()
    ctf.searchsploit()
    ctf.check_webservers()
    if len(ctf.web_ports) > 0:
        pass
        ctf.start_fuzzing()
    else:
        print()
        rprint('[FUZZING] No web servers to fuzz!')
        print()

    # pprint(ctf.scan_results)
    # pprint(ctf.ports)
    # pprint(ctf.open_ports)
    # pprint(ctf.web_ports)

    return









if __name__ == '__main__':
    main()














    # def parse_results(self, target: dict):
    #     """Parse the results of the Nmap scan and display 
    #     on the command line which ports are open.
    #     If any http servers are running, begin fuzzing with FFUF
    #     """
    #     web_server_ports = []
    #     for protocol in target.all_protocols():
    #         rprint()
    #         rprint('==============================')
    #         rprint(f"[bold]{protocol.upper()} Ports")
    #         rprint('==============================')
    #         for port, value in target[protocol].items():
    #             if value['state'] != 'closed':
    #                 rprint(f"Port\t: {port}")
    #                 if value['state'] == 'open':
    #                     rprint(f"State\t: [bold]{value['state']}")
    #                 else:
    #                     rprint(f"State\t: [yellow]{value['state']}")
    #                 rprint(f"Name\t: {value['name']}")
    #                 rprint(f"Product\t: {value['product']}")
    #                 rprint(f"Version\t: [cyan bold]{value['version']}")
    #                 rprint()
    #             if value['name'] == 'http':
    #                 web_server_ports.append(port)

    #     with Progress(transient=True) as progress:
    #         for port in web_server_ports:
    #             task = progress.add_task("[cyan]Fuzzing...", total=None)
    #             self.run_ffuf(port)










# BANNER = """
#  ______     ______   ______       ______   __     __    __     ______    
# /\  ___\   /\__  _\ /\  ___\     /\__  _\ /\ \   /\ "-./  \   /\  ___\   
# \ \ \____  \/_/\ \/ \ \  __\     \/_/\ \/ \ \ \  \ \ \-./\ \  \ \  __\   
#  \ \_____\    \ \_\  \ \_\          \ \_\  \ \_\  \ \_\ \ \_\  \ \_____\ 
#   \/_____/     \/_/   \/_/           \/_/   \/_/   \/_/  \/_/   \/_____/ 

# ========================================================================
# Version 1.0
# """

# TARGET_IP   = sys.argv[1]
# DIR_NAME    = sys.argv[2]
# HOME        = Path().home()
# DIR_PATH    = f"{HOME}/ctf/thm/{DIR_NAME}"
# SCANS       = f"{DIR_PATH}/scans"
# WORDLIST    = '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt'
# nm          = nmap.PortScanner()


# def make_dirs():
#     """Create the directory and notes file for the CTF."""
#     try:
#         os.makedirs(SCANS, exist_ok=False)
#         os.mknod(f"{DIR_PATH}/notes")
#     except FileExistsError:
#         raise FileAlreadyExists
#     except OSError:
#         raise FileAlreadyExists
#     return


# def validate_ip(ip: str):
#     """Checks if user-supplied IP address is legit."""
#     try:
#         ip = ipaddress.ip_address(ip)
#     except ValueError:
#         raise IPAddressInvalid 
#     else:
#         return ip


# def scan_target():
#     """Nmap scan of target IP"""
#     arguments = f"--top-ports 1000 -sV -vv -oN {SCANS}/sV"
#     nm.scan(
#         hosts = TARGET_IP, 
#         ports = '21,22,80,139,445,3306', 
#         arguments = arguments
#     )


#     rprint('[SCANNING] Starting Nmap Scan: ')
#     for host in nm.all_hosts():
#         rprint(f"[HOST] {host}")
#     rprint(f"[ARGS] {nm.command_line()}")

#     try:
#         target = nm[TARGET_IP]
#     except KeyError:
#         raise IPAddressInvalid

#     return target


# def parse_results(target: dict):
#     """Parse the results of the Nmap scan and display on the command line which ports are open."""
#     for protocol in target.all_protocols():
#         rprint()
#         rprint(f"{protocol.upper()} Ports")
#         rprint('==============================')
#         for port, value in target[protocol].items():
#             if value['state'] == 'open':
#                 rprint(f"Port\t: {port}")
#                 rprint(f"State\t: {value['state']}")
#                 rprint(f"Name\t: {value['name']}")
#                 rprint(f"Product\t: {value['product']}")
#                 rprint(f"Version\t: {value['version']}")
#                 rprint()
#             if port == 80 or port == 8080 or port == 8000 or port == 8888:
#                 run_ffuf(port)


# def run_ffuf(port: int):
#     """Runs FFUF with a default wordlist on any webserver ports"""
#     rprint()
#     rprint('==============================')
#     rprint(f"Fuzzing on port:\t{port}")
#     url = f"http://{TARGET_IP}:{port}"

#     result = subprocess.run(['ffuf', '-u', f"{url}/FUZZ", '-w', f"{WORDLIST}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#     result_text = result.stdout.decode('utf-8')
#     rprint()
#     rprint(result_text)
#     rprint()










