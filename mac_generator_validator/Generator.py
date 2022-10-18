import json
import os.path
import random
import typing
from enum import Enum
from typing import List
import requests

from mac_generator_validator.Exceptions import FormatErrorUnknown


class Format(Enum):
    """type of MAC address formats"""
    HYPHEN = 1
    COLON = 2
    PERIOD = 3
    CISCO = 4
    NONE = 5
    UNKNOWN = 6


class GeneratorMac:
    """
    Supported MAC address formats:
       MM:MM:MM:SS:SS:SS
       MM-MM-MM-SS-SS-SS
       MMMM.MMSS.SSSS
       MMMMMMSSSSSS
    """
    hexadecimal = "0123456789ABCDEF"
    validator_url = "http://macvendors.co/api/"
    headers = {'User-Agent': 'API Browser',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'accept-encoding': 'gzip, deflate',
                    'accept-language': 'en-US,en;q=0.8',
                    "referer": f"https://google.com/"}
    @staticmethod
    def generate_mac_address(mac_type=None, trimmed=False,
                             format_type: Format = None, lowercase=False,
                             generate_partial=False, quantity=1) -> List[str]:

        if not mac_type and not format_type:
            logger.error("No MAC address type or format type specified, defaulting to colon format")
            format_type = Format.COLON
        elif mac_type and not format_type:
            format_type = GeneratorMac.get_format(mac_type)
        elif not mac_type and format_type:
            format_type = GeneratorMac.get_mac_format(mac_type)
        else:
            raise ValueError("Format type and MAC address type specified, cannot chose both")

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
        for _ in range(quantity):
            yield GeneratorMac.generate_address(format_type, lowercase, trimmed, generate_partial)

    @staticmethod
    def generate_address( format_type: Format,
                         lowercase: bool, trimmed_flag,
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
            not_formatted = GeneratorMac.build_random_nic()
        else:
            not_formatted = GeneratorMac.build_random_twelve_digit()
        mac = GeneratorMac.build_mac_with_separator(
            GeneratorMac._set_lettercase(not_formatted, lowercase=lowercase), format_type
        )
        if trimmed_flag:
            mac = GeneratorMac._trim_separator(mac)
        if len(mac) <= 12 and not generate_partial:
            raise ValueError(f"MAC must be 12 digits but found {len(mac)}")
        return mac

    @staticmethod
    def _trim_separator(mac: str) -> str:
        """removes separator from MAC address
        :param mac: the mac address
        :return: the mac address without separator
        """
        return mac.translate(str.maketrans("", "", ":-."))
    @staticmethod
    def _set_lettercase(string: str, lowercase: bool) -> str:
        """determines lettercase for MAC address
        :param string: the mac address
        :return: the mac address with the lettercase
        """
        return string.upper() if not lowercase else string.lower()

    @staticmethod
    def _ins(source: str, insert: str, position: int) -> str:
        """inserts value at a certain position in the source
        :param source: the source string
        :param insert: the value to insert
        :param position: the position to insert the value
        :return: the source string with the value inserted
        """
        return source[:position] + insert + source[position:]
    @staticmethod
    def build_mac_with_separator( mac: str, _format: Format) -> str:
        """
        builds the type of separator used
        :param mac: the mac address
        :param _format: the format of the mac address
        :return: the mac address with the separator
        """
        if _format == Format.HYPHEN:
            return GeneratorMac._ins(
                GeneratorMac._ins(
                    GeneratorMac._ins(GeneratorMac._ins(GeneratorMac._ins(mac, "-", 2), "-", 5), "-", 8),
                    "-",
                    11,
                ),
                "-",
                14,
            )
        if _format == Format.COLON:
            return GeneratorMac._ins(
                GeneratorMac._ins(
                    GeneratorMac._ins(GeneratorMac._ins(GeneratorMac._ins(mac, ":", 2), ":", 5), ":", 8),
                    ":",
                    11,
                ),
                ":",
                14,
            )
        if _format == Format.PERIOD:
            return GeneratorMac._ins(
                GeneratorMac._ins(
                    GeneratorMac._ins(GeneratorMac._ins(GeneratorMac._ins(mac, ".", 2), ".", 5), ".", 8),
                    ".",
                    11,
                ),
                ".",
                14,
            )
        if _format == Format.CISCO:
            return GeneratorMac._ins(GeneratorMac._ins(mac, ".", 4), ".", 9)
        if _format == Format.NONE:
            return mac
        if _format == Format.UNKNOWN:
            raise FormatErrorUnknown("Unknown MAC format")
    @staticmethod
    def get_mac_format( mac: str) -> Format:
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
    @staticmethod
    def build_random_nic() -> str:
        """randomize 6-digit NIC portion of a mac addr
        :return: the mac address with the random NIC portion
        """
        random_nic = GeneratorMac.get_random_json_from_array().get('mac')
        # for c in range(0, 6):
        #     random_nic += random.choice(GeneratorMac.hexadecimal)
        random_nic= GeneratorMac._trim_separator(random_nic)

        return random_nic
    @staticmethod
    def build_random_twelve_digit() -> str:
        """randomize 12-digit mac
        :return: the mac address with the random 12-digit mac
        """
        mac = GeneratorMac.build_random_nic()
        for number in range(0, 6):
            mac += random.choice(GeneratorMac.hexadecimal)
        return mac

    @staticmethod
    def get_random_json_from_array() -> json:
        """get the random vendor from the list of vendors
        :param mac: the mac address
        :return: the random vendor
        """
        vendors = GeneratorMac.get_vendors()
        return random.choice(vendors)
    @staticmethod
    def get_vendors()->json:
        """get the list of vendors
                :return: the list of vendors
        """
        root_dir = os.path.dirname(os.path.abspath(__file__))
        return json.load(open(os.path.join(root_dir, "vendors_mac.json"), "r"))


    @staticmethod
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
            return Format.UNKNOWN
    @staticmethod
    def get_mac_info(mac_addr: str) :
        """get the mac address info
        :param mac_addr: the mac address
        :return: the validation of the mac address
        """
        response = requests.get(GeneratorMac.validator_url + mac_addr,
                               headers=GeneratorMac.headers)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    @staticmethod
    def get_mac_vendor(mac_addr: str) -> typing.Optional[str]:
        """get the vendor of the mac address
        :param mac_addr: the mac address
        :return: the vendor of the mac address
        """
        response = requests.get(GeneratorMac.validator_url + mac_addr,
                               headers=GeneratorMac.headers)
        if response.status_code == 200:
            return response.json().get('result').get('company')

    @staticmethod
    def get_mac_prefix(mac_addr: str)  -> typing.Optional[str]:
        """get the type of the mac address
        :param mac_addr: the mac address
        :return: the type of the mac address
        """
        request = requests.get(GeneratorMac.validator_url + mac_addr,
                               headers=GeneratorMac.headers)
        if request.status_code == 200:
            return request.json().get('result').get('mac_prefix')

    @staticmethod
    def is_mac_addr_valid(mac_addr: str) -> bool:
        """validate the mac address
        :param mac_addr: the mac address
        :return: the validation of the mac address
        """
        response = requests.get(GeneratorMac.validator_url + mac_addr,
                               headers=GeneratorMac.headers)
        if response.status_code == 200:
            print(response.json())
            if response.json().get('result').get('company'):
                return True
            elif response.json().get('result').get('error'):
                return False
            #you can add more conditions here based on how do you want
            #to handle the response from the API on error
            else:
                return False
    @staticmethod
    def get_start_hex(mac_addr: str) -> typing.Optional[str]:
        """get the start hex of the mac address
        :param mac_addr: the mac address
        :return: the start hex of the mac address
        """
        response = requests.get(GeneratorMac.validator_url + mac_addr,
                                headers=GeneratorMac.headers)
        if response.status_code == 200:
            return response.json().get('result').get('start_hex')
    @staticmethod
    def get_end_hex(mac_addr: str) -> typing.Optional[str]:
        """get the end hex of the mac address
        :param mac_addr: the mac address
        :return: the end hex of the mac address
        """
        response = requests.get(GeneratorMac.validator_url + mac_addr,
                                headers=GeneratorMac.headers)
        if response.status_code == 200:
            return response.json().get('result').get('end_hex')
    @staticmethod
    def get_country(mac_addr: str) -> typing.Optional[str]:
        """get the country of the mac address
        :param mac_addr: the mac address
        :return: the country of the mac address
        """
        response = requests.get(GeneratorMac.validator_url + mac_addr,
                                headers=GeneratorMac.headers)
        if response.status_code == 200:
            return response.json().get('result').get('country')
    @staticmethod
    def get_type(mac_addr: str) -> typing.Optional[str]:
        """get the type of the mac address
        :param mac_addr: the mac address
        :return: the type of the mac address
        """
        response = requests.get(GeneratorMac.validator_url + mac_addr,
                                headers=GeneratorMac.headers)
        if response.status_code == 200:
            return response.json().get('result').get('type')


if __name__ == "__main__":

    # [print(x) for x in GeneratorMac.generate_mac_address(quantity=10)]
    # print(GeneratorMac.validate_mac_addr(list(GeneratorMac.generate_mac_address(quantity=1))[0]))
    # print(GeneratorMac.validate_mac_addr('01:00:00:00:00:20'))
    print(GeneratorMac.is_mac_addr_valid('00:00:00:00:00:00'))
    # print(GeneratorMac.get_vendors())
    # print(GeneratorMac.get_random_json_from_array())