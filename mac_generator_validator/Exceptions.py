class FormatErrorUnknown(Exception):
    """
    Format Error Unknown
    """

class InvalidMacError(Exception):
    pass


class VendorNotFoundError(KeyError):
    def __init__(self, mac):
        self.mac = mac

    def __str__(self):
        return f"The vendor for MAC {self.mac} could not be found. " \
               f"Either it's not registered or the local list is out of date. Try MacLookup().update_vendors()"
