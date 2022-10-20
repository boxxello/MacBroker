import asyncio
import re
import json
import os.path
import random
import typing
from datetime import datetime
from enum import Enum
from typing import List, Tuple, Any
import sys
import aiofiles
import aiohttp

from mac_generator_validator.loggers import get_logger, enable_debug_logging

from mac_generator_validator.Exceptions import FormatErrorUnknown, InvalidMacError, VendorNotFoundError

logger = get_logger(__name__)

"""
Supported MAC address formats:
   MM:MM:MM:SS:SS:SS
   MM-MM-MM-SS-SS-SS
   MMMM.MMSS.SSSS
   MMMMMMSSSSSS
"""


class Format(Enum):
    """type of MAC address formats"""
    HYPHEN = 1
    COLON = 2
    PERIOD = 3
    CISCO = 4
    NONE = 5
    UNKNOWN = 6


HEXADECIMAL = "0123456789ABCDEF"


def set_lettercase(string: str, lowercase: bool) -> str:
    """determines lettercase for MAC address
    :param string: the mac address
    :return: the mac address with the lettercase
    """
    return string.upper() if not lowercase else string.lower()


def ins_value(source: str, insert: str, position: int) -> str:
    """inserts value at a certain position in the source
    :param source: the source string
    :param insert: the value to insert
    :param position: the position to insert the value
    :return: the source string with the value inserted
    """
    return source[:position] + insert + source[position:]





def get_mac_format(mac: str) -> Format:
    """set the mac format style
    :param mac: the mac address
    :return: the format of the mac address
    """
    if mac.count("-") == 5 and "." not in mac and ":" not in mac:
        return Format.HYPHEN
    if mac.count(":") == 5 and "." not in mac and "-" not in mac:
        return Format.COLON
    if mac.count(".") == 5 and ":" not in mac and "-" not in mac:
        return Format.PERIOD
    if mac.count(".") == 2 and ":" not in mac and "-" not in mac:
        return Format.CISCO
    if len(mac) == 12:
        return Format.NONE
    if "." not in mac and ":" not in mac and "-" not in mac:
        return Format.UNKNOWN
    else:
        return Format.NONE


def build_mac_with_separator(mac: str, _format: Format) -> str:
    """
    builds the type of separator used
    :param mac: the mac address
    :param _format: the format of the mac address
    :return: the mac address with the separator
    """
    if _format == Format.HYPHEN:
        return ins_value(
            ins_value(
                ins_value(ins_value(ins_value(mac, "-", 2), "-", 5), "-", 8),
                "-",
                11,
            ),
            "-",
            14,
        )
    if _format == Format.COLON:
        return ins_value(
            ins_value(
                ins_value(ins_value(ins_value(mac, ":", 2), ":", 5), ":", 8),
                ":",
                11,
            ),
            ":",
            14,
        )
    if _format == Format.PERIOD:
        return ins_value(
            ins_value(
                ins_value(ins_value(ins_value(mac, ".", 2), ".", 5), ".", 8),
                ".",
                11,
            ),
            ".",
            14,
        )
    if _format == Format.CISCO:
        return ins_value(ins_value(mac, ".", 4), ".", 9)
    if _format == Format.NONE:
        return mac
    if _format == Format.UNKNOWN:
        raise FormatErrorUnknown("Unknown MAC format")

def get_format(mac_type) -> Format:
    """get format of MAC address
    :param mac_type: the type of mac address
    :return: the format of the mac address
    """
    if mac_type.find(":") != -1:
        return Format.COLON
    elif mac_type.find("-") != -1:
        return Format.HYPHEN
    elif mac_type.find(".") != -1:
        return Format.PERIOD
    elif mac_type.find("") != -1:
        return Format.CISCO
    elif mac_type.find("") != -1:
        return Format.NONE
    else:
        raise FormatErrorUnknown("Unknown MAC format")


def sanitise(_mac):
    mac = _mac.translate(str.maketrans("", "", ":-.")).upper()
    try:
        int(mac, 16)
    except ValueError:
        raise InvalidMacError(f"{_mac} contains unexpected character")
    if len(mac) > 12:
        raise InvalidMacError(f"{_mac} is not a valid MAC address (too long)")
    return mac


OUI_URL = "http://standards-oui.ieee.org/oui.txt"


class BaseMacLookup(object):
    cache_path = os.path.expanduser('~/.cache/mac-vendors.json')
    def get_last_updated(self):
        vendors_location = self.find_vendors_list()
        if vendors_location:
            return datetime.fromtimestamp(os.path.getmtime(vendors_location))

    def find_vendors_list(self):
        possible_locations = [
            BaseMacLookup.cache_path,
            sys.prefix + "/cache/mac-vendors.json",
            os.path.dirname(__file__) + "/../../cache/mac-vendors.json",
            os.path.dirname(__file__) + "/../../../cache/mac-vendors.json",
        ]

        for location in possible_locations:
            if os.path.exists(location):
                return location


class AsyncMacLookup(BaseMacLookup):
    def __init__(self):
        self.prefixes = None

    async def update_vendors(self, url=OUI_URL):
        logger.debug("Downloading MAC vendor list")
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                self.prefixes = []
                while True:
                    line = await response.content.readline()

                    if not line:
                        break
                    if b"(base 16)" in line:
                        prefix, vendor = (i.strip() for i in line.split(b"(base 16)", 1))
                        self.prefixes.append({"vendor": vendor.decode(), "mac": prefix.decode()})
                    elif group := re.search(b"[A-Z]{2}", line):
                        if self.prefixes:
                            self.prefixes[-1]["nationality"] = group.group(0).decode().strip()

        async with aiofiles.open(AsyncMacLookup.cache_path, mode='w') as f:
            await f.write(json.dumps(self.prefixes, indent=4))

    async def generate_n_mac_address(self,
                             format_type: Format = None, lowercase=False,
                             generate_partial=False, quantity=1) :
        if not format_type:
            logger.error("No MAC address type or format type specified, defaulting to colon format")
            format_type = Format.COLON
        try:
            lowercase = bool(lowercase)
        except ValueError:
            logger.error("lowercase must be a boolean, defaulting to false")
            lowercase = False
        if quantity:
            try:
                quantity = int(quantity)
            except ValueError:
                logger.error("quantity must be an integer, defaulting to 1")
                quantity = 1

        return [ await self.generate_mac_address(format_type, lowercase,  generate_partial) for _ in range(quantity)]


    async def generate_mac_address(self, format_type: Format,
                         lowercase: bool,
                         generate_partial) -> str:
        """
        Generate a random MAC address
        :param format_type:
        :param lowercase:
        :param trimmed_flag:
        :param generate_partial:
        :return:
        """
        if generate_partial:
            not_formatted = await self.build_random_nic()
        else:
            not_formatted = await self.build_random_twelve_digit()
        mac = build_mac_with_separator(
            set_lettercase(not_formatted, lowercase=lowercase), format_type
        )
        if len(mac) < 12 and not generate_partial:
            raise ValueError(f"MAC must be 12 digits but found {len(mac)}")
        return mac
    async def build_random_nic(self) -> str:
        if not self.prefixes:
            await self.load_vendors()
        random_nic = (await self.get_random_vendor()).get("mac")
        random_nic = sanitise(random_nic)

        return random_nic

    async def build_random_twelve_digit(self) -> str:
        """randomize 12-digit mac
        :return: the mac address with the random 12-digit mac
        """
        mac = await self.build_random_nic()
        for number in range(0, 6):
            mac += random.choice(HEXADECIMAL)
        return mac


    async def get_vendors(self) -> json:
        if not self.prefixes:
            await self.load_vendors()
        return self.prefixes

    async def get_random_vendor(self) -> dict:
        if not self.prefixes:
            await self.load_vendors()
        return random.choice(self.prefixes)

    async def load_vendors(self):
        self.prefixes = []

        vendors_location = self.find_vendors_list()
        if vendors_location:
            logger.debug("Loading vendor list from {}".format(vendors_location))
            async with aiofiles.open(vendors_location, mode='r') as f:
                self.prefixes = json.loads(await f.read())

        else:
            try:
                os.makedirs("/".join(AsyncMacLookup.cache_path.split("/")[:-1]))
            except OSError:
                pass
            await self.update_vendors()
        logger.debug("Vendor list successfully loaded: {} entries".format(len(self.prefixes)))

    async def lookup(self, mac):
        mac = sanitise(mac)
        if not self.prefixes:
            await self.load_vendors()
        try:
            return next(i for i in self.prefixes if mac.startswith(i["mac"]))["vendor"]
        except KeyError:
            raise VendorNotFoundError(mac)
        except StopIteration:
            raise VendorNotFoundError(mac)

    async def look_up_nationality(self, mac):
        mac = sanitise(mac)
        if not self.prefixes:
            await self.load_vendors()
        try:
            return any(mac.startswith(i["mac"]) for i in self.prefixes)
        except KeyError:
            raise VendorNotFoundError(mac)
        except StopIteration:
            raise VendorNotFoundError(mac)

    async def is_mac_addr_valid(self, mac):
        """
        Check if the mac address is valid
        :param mac: the mac address
        :return: True if the mac address is valid, False otherwise
        """
        mac = sanitise(mac)
        if not self.prefixes:
            await self.load_vendors()
        try:
            return True if any(mac.startswith(i["mac"]) for i in self.prefixes) else False
        except KeyError:
            raise VendorNotFoundError(mac)
        except StopIteration:
            raise VendorNotFoundError(mac)

    async def is_mac_addr_list_valid(self, macs: list) -> List[Tuple[bool, Any]]:
        """
        Check if the mac address is valid
        :param mac: the mac address
        :return: Tuple mac address and bool valid or invalid
        """
        return [(True, mac) if self.is_mac_addr_valid(mac) else (False, mac) for mac in macs]


class MacLookup(BaseMacLookup):
    def __init__(self):
        self.async_lookup = AsyncMacLookup()
        try:
            self.loop = asyncio.get_event_loop()
        except RuntimeError:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

    def update_vendors(self, url=OUI_URL):
        return self.loop.run_until_complete(self.async_lookup.update_vendors(url))

    def lookup(self, mac):
        return self.loop.run_until_complete(self.async_lookup.lookup(mac))

    def look_up_nationality(self, mac):
        return self.loop.run_until_complete(self.async_lookup.look_up_nationality(mac))

    def load_vendors(self):
        return self.loop.run_until_complete(self.async_lookup.load_vendors())

    def is_mac_addr_valid(self, mac):
        return self.loop.run_until_complete(self.async_lookup.is_mac_addr_valid(mac))

    def is_mac_addr_list_valid(self, macs: list) -> List[Tuple[bool, Any]]:
        return self.loop.run_until_complete(self.async_lookup.is_mac_addr_list_valid(macs))

    def build_random_nic(self) -> str:
        return self.loop.run_until_complete(self.async_lookup.build_random_nic())

    def build_random_twelve_digit(self) -> str:
        return self.loop.run_until_complete(self.async_lookup.build_random_twelve_digit())

    def get_vendors(self) -> json:
        return self.loop.run_until_complete(self.async_lookup.get_vendors())

    def get_random_vendor(self) -> dict:
        return self.loop.run_until_complete(self.async_lookup.get_random_vendor())

    def generate_n_mac_addresses(self,  format_type:Format= Format.COLON,
                                 lowercase: bool = False, generate_partial: bool = False, quantity:int=1) -> List[str]:
        return self.loop.run_until_complete(self.async_lookup.generate_n_mac_address( format_type,
                                                                                     lowercase, generate_partial, quantity))



if __name__ == "__main__":
    enable_debug_logging()
    loop = asyncio.get_event_loop()
    print(MacLookup().lookup("00:00:00:00:00:00"))
    print(MacLookup().build_random_nic())
    print(MacLookup().build_random_twelve_digit())
    print(MacLookup().generate_n_mac_addresses(quantity=10))