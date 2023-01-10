

class IPAddressInvalid(Exception):
    """Raised when IP Address supplied by user is invalid."""
    message = '\n[ERROR] Invalid or unreachable IP Address. Bruh.\n'
    pass


class FileAlreadyExists(Exception):
    """Raised when make_dirs() function tries to create a new filepath that already exists."""
    message = '\n[ERROR] File path already exists. Have you done this CTF already? Bruh.'
    pass


class ScanNotFoundError(Exception):
    """Raised when the nmap scan result is not found"""
    message = "\n[ERROR] Where's the Nmap scan, bro? Like... where's the scan???"
    pass