class FormatErrorUnknown(Exception):
    """
    Format Error Unknown
    """

class NoDateFoundCacheError(Exception):
    """
    No Date Found Cache Error, couldn't retrieve the modified date from the cache file
    """
class InvalidMacError(Exception):
    """
    Invalid MAC Error, the MAC address is invalid
    """


class VendorNotFoundError(KeyError):
    def __init__(self, mac):
        self.mac = mac

    def __str__(self):
        return f"The vendor for MAC {self.mac} could not be found. " \
               f"Either it's not registered or the local json is out of date. Try MacBroker().update_vendors()"
