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

from mac_generator_validator.Utils_methods import is_path_exists_or_creatable
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

def load_macs_from_file(filename: str) -> List[str]:
    """load macs from file
    :param filename: the filename to load
    :return: the list of macs
    """
    if not os.path.isfile(filename):
        raise FileNotFoundError("File not found")
    with open(filename, "r") as file:
        return file.read().splitlines()

def save_macs_to_file(filename: str, macs: List[str]) -> None:
    """save macs to file
    :param filename: the filename to save to
    :param macs: the list of macs
    """
    if is_path_exists_or_creatable(filename):
        with open(filename, "w") as file:
            file.write("\n".join(macs))

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


def sanitise(input_mac:str)-> str:
    """
    sanitise the mac address
    :param _mac:
    :return:
    """
    mac = input_mac.translate(str.maketrans("", "", ":-.")).upper()
    try:
        int(mac, 16)
    except ValueError:
        raise InvalidMacError(f"{input_mac} contains unexpected character")
    if len(mac) > 12:
        raise InvalidMacError(f"{input_mac} is not a valid MAC address (too long)")
    return mac


OUI_URL = "http://standards-oui.ieee.org/oui.txt"


class BaseMacBroker(object):
    cache_path = os.path.expanduser('~/.cache/mac-vendors.json')
    def get_last_updated(self)-> datetime:
        """
        get the last updated date of the cache
        :return: the last timestamp of the cached file
        """
        vendors_location = self.find_vendors_list()
        if vendors_location:
            return datetime.fromtimestamp(os.path.getmtime(vendors_location))

    def find_vendors_list(self)-> str:
        """
        find the vendors list in cache
        :return: the path to the vendors list
        """
        possible_locations = [
            BaseMacBroker.cache_path,
            sys.prefix + "/cache/mac-vendors.json",
            os.path.dirname(__file__) + "/../../cache/mac-vendors.json",
            os.path.dirname(__file__) + "/../../../cache/mac-vendors.json",
        ]

        for location in possible_locations:
            if os.path.exists(location):
                return location


class AsyncMacBroker(BaseMacBroker):
    def __init__(self):
        self.prefixes = None

    async def update_vendors(self, url=OUI_URL):
        """
        Update the vendors list by downloading the latest version from the OUI
        :param url: the url to download the vendors list from
        """
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

        async with aiofiles.open(AsyncMacBroker.cache_path, mode='w') as f:
            await f.write(json.dumps(self.prefixes, indent=4))

    async def generate_n_mac_address(self,
                             format_type: Format = None, lowercase=False,
                             generate_partial=False, quantity=1) :
        """
        function to generate n mac addresses
        :param format_type: Format to generate the mac address
        :param lowercase: if the mac address should be lowercase
        :param generate_partial: if the mac address should be partial, i.e. 00:00:00
        :param quantity: quantity of mac addresses to generate
        :return: List of valid mac addresses
        """
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
        Function to generate 1 mac address
        :param format_type: Format to generate the mac address
        :param lowercase: if the mac address should be lowercase
        :param generate_partial: if the mac address should be partial, i.e. 00:00:00
        :return: A valid mac address
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
        """
        Function to get a random prefix from class instance and return it sanitized
        :return: random sanitized prefix
        """
        if not self.prefixes:
            await self.load_vendors()
        random_nic = await self.get_random_mac_prefix()
        random_nic = sanitise(random_nic)

        return random_nic

    async def build_random_twelve_digit(self) -> str:
        """
        Randomize 12-digit mac
        :return: the mac address with the random 12-digit mac
        """
        mac = await self.build_random_nic()
        for number in range(0, 6):
            mac += random.choice(HEXADECIMAL)
        return mac


    async def get_all_vendors(self) -> List[str]:
        """
        Get all vendors
        :return: a list of all vendors
        """

        if not self.prefixes:
            await self.load_vendors()
        return [x.get('vendor') for x in self.prefixes]

    async def get_all_prefixes(self) -> List[str]:
        """
        Get all prefixes
        :return:
        """
        if not self.prefixes:
            await self.load_vendors()
        return [x.get('mac') for x in self.prefixes]
    async def get_random_mac_prefix(self) -> str:
        """
        Get a random mac prefix
        :return: random mac prefix
        """
        if not self.prefixes:
            await self.load_vendors()
        return random.choice(await self.get_all_prefixes())

    async def get_random_vendor(self) -> str:
        """
        Get a random vendor
        :return: random vendor
        """
        if not self.prefixes:
            await self.load_vendors()
        return random.choice(await self.get_all_vendors())

    async def load_vendors(self):
        """
        Load vendors in class instance from cache and if not found download them
        """
        self.prefixes = []

        vendors_location = self.find_vendors_list()
        if vendors_location:
            logger.debug(f"Loading vendor list from {vendors_location}")
            async with aiofiles.open(vendors_location, mode='r') as f:
                self.prefixes = json.loads(await f.read())

        else:
            try:
                os.makedirs("/".join(AsyncMacBroker.cache_path.split("/")[:-1]))
            except OSError:
                pass
            await self.update_vendors()
        logger.debug(f"Vendor list successfully loaded: {len(self.prefixes)} entries")

    async def lookup(self, mac)->str:
        """
        Lookup a mac address and find its vendor
        :param mac: mac to check
        :return: vendor
        :raise KeyError | VendorNotFoundError : if mac is not a valid mac address
        :rai
        """
        mac = sanitise(mac)
        if not self.prefixes:
            await self.load_vendors()
        try:
            return next(i for i in self.prefixes if mac.startswith(i["mac"]))["vendor"]
        except KeyError:
            raise VendorNotFoundError(mac)
        except StopIteration:
            raise VendorNotFoundError(mac)

    async def look_up_nationality(self, mac) -> str:
        """
        Lookup a mac address and find its nationality
        :param mac: mac to check
        :return: nationality
        :raise KeyError | VendorNotFoundError : if mac is not a valid mac address
        """
        mac = sanitise(mac)
        if not self.prefixes:
            await self.load_vendors()
        try:
            return next(i for i in self.prefixes if mac.startswith(i["mac"]))["nationality"]
        except KeyError:
            raise VendorNotFoundError(mac)
        except StopIteration:
            raise VendorNotFoundError(mac)

    async def is_mac_addr_valid(self, mac)->bool:
        """
        Check if the mac address is valid
        :param mac: mac address to check
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
        :return: A list of tuples with [mac|bool] format
        """
        return [(True, mac) if await self.is_mac_addr_valid(mac) else (False, mac) for mac in macs]


class MacBroker(BaseMacBroker):
    """
    MacBroker class
    """
    def __init__(self):
        self.async_lookup = AsyncMacBroker()
        try:
            self.loop = asyncio.get_event_loop()
        except RuntimeError:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

    def update_vendors(self, url=OUI_URL):
        """
        Updates vendors from url and loades them in class instance and stores them in cache
        :param url: OUI url to download the prefix/vendors from
        """
        return self.loop.run_until_complete(self.async_lookup.update_vendors(url))

    def lookup(self, mac):
        """
        wrapper function to look up a mac address and find its vendor
        :param mac: mac to check
        :return: find its vendor
        """
        return self.loop.run_until_complete(self.async_lookup.lookup(mac))

    def look_up_nationality(self, mac):
        """
        wrapper function to look up a mac address and find the nationality
        :param mac: mac to check
        :return: mac nationality if found
        :raise KeyError | VendorNotFoundError : if mac is not a valid mac address
        """
        return self.loop.run_until_complete(self.async_lookup.look_up_nationality(mac))

    def load_vendors(self):
        """
        wrapper function to load vendors in class instance from cache and if not found download them
        """
        return self.loop.run_until_complete(self.async_lookup.load_vendors())

    def is_mac_addr_valid(self, mac):
        """
        wrapper function to check if the mac address is valid
        :param mac: mac address to check
        :return: bool if the mac address is valid or not
        """
        return self.loop.run_until_complete(self.async_lookup.is_mac_addr_valid(mac))

    def is_mac_addr_list_valid(self, macs: list) -> List[Tuple[bool, Any]]:
        """
        wrapper function to check if the mac address list inputted is valid
        :param macs: list of mac addresses to check
        :return: List of tuples with [mac|bool] format
        """
        return self.loop.run_until_complete(self.async_lookup.is_mac_addr_list_valid(macs))

    def build_random_nic(self) -> str:
        """
        wrapper function to get a random prefix from the and return it sanitized
        :return: random sanitized prefix
        """
        return self.loop.run_until_complete(self.async_lookup.build_random_nic())

    def build_random_twelve_digit(self) -> str:
        """
        wrapper function to build a random valid mac address
        :return: valid mac address
        """
        return self.loop.run_until_complete(self.async_lookup.build_random_twelve_digit())

    def get_random_vendor(self) -> dict:
        """
        wrapper function to get a random vendor from the list
        :return: random vendor
        """
        return self.loop.run_until_complete(self.async_lookup.get_random_vendor())

    def get_random_mac_prefix(self) -> dict:
        """
        wrapper function to get a random mac prefix from the list
        :return:
        """
        return self.loop.run_until_complete(self.async_lookup.get_random_mac_prefix())

    def get_all_prefixes(self) -> List[str]:
        """
        wrapper function to get all valid prefixes from cached file
        :return: list of prefixes
        """
        return self.loop.run_until_complete(self.async_lookup.get_all_prefixes())

    def get_all_vendors(self) -> List[str]:
        """
        wrapper function to get all vendors from cached file
        :return: a list of all the vendors from cached file
        """
        return self.loop.run_until_complete(self.async_lookup.get_all_vendors())

    def generate_n_mac_addresses(self,  format_type:Format= Format.COLON,
                                 lowercase: bool = False, generate_partial: bool = False, quantity:int=1) -> List[str]:
        """
        wrapper function to generate n mac addresses
        :param format_type: Format to generate the mac address
        :param lowercase: if the mac address should be lowercase
        :param generate_partial: if the mac address should be partial, i.e. 00:00:00
        :param quantity: quantity of mac addresses to generate
        :return: List of valid mac addresses
        """
        return self.loop.run_until_complete(self.async_lookup.generate_n_mac_address( format_type,
                                                                                     lowercase, generate_partial, quantity))



if __name__ == "__main__":
    enable_debug_logging()
    loop = asyncio.get_event_loop()
    logger.info(MacBroker().lookup("00:00:00:00:00:00"))
    logger.info(MacBroker().build_random_nic())
    logger.info(MacBroker().build_random_twelve_digit())
    logger.info(MacBroker().generate_n_mac_addresses(quantity=10))
    logger.info(MacBroker().get_all_vendors())
    logger.info(MacBroker().get_all_prefixes())
    logger.info(MacBroker().get_random_vendor())
    logger.info(MacBroker().get_random_mac_prefix())
    logger.info(MacBroker().is_mac_addr_valid("00:00:00:00:00:00"))
    logger.info(MacBroker().is_mac_addr_list_valid(["00:00:00:00:00:00", "00:00:00:00:00:00"]))