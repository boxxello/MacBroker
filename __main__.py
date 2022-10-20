import argparse
from argparse import Namespace

from mac_generator_validator.Generator import Format, MacLookup, load_macs_from_file
from mac_generator_validator.loggers import get_logger, enable_debug_logging

logger = get_logger(__name__)


def parse_args() -> Namespace:
    parser = argparse.ArgumentParser(description='Mac Generator & Validator')
    parser.add_argument(
        "--input",
        "-i",
        required=False,
        type=str,
        help="Input file",
    )
    parser.add_argument(
        "--output",
        "-o",
        required=False,
        type=str,
        help="Output file",
    )
    parser.add_argument(
        "--debug",
        "-d",
        type=bool,
        default=False,
        help="Enable debug logging",
    )
    parser.add_argument(
        "--validate",
        "-v",
        type=bool,
        default=False,
        help="Validate MAC addresses",
    )
    parser.add_argument(
        "--generate",
        "-g",
        type=bool,
        default=False,
        help="Generate MAC addresses",
    )
    parser.add_argument(
        "--quantity",
        "-q",
        type=int,
        help="Number of MAC addresses to generate",
    )
    parser.add_argument(
        "--type",
        "-t",
        type=str,
        help="Type of MAC address to generate",
    )
    args = parser.parse_args()
    logger.info(args)

    return args


def parse_type_argument(str) -> Format:
    """
    Parse the type argument from the command line

    :param str: The type argument
    :return: The format
    """
    if str:
        if str == "hyphen":
            return Format.HYPHEN
        elif str == "colon":
            return Format.COLON
        elif str == "period":
            return Format.PERIOD
        elif str == "cisco":
            return Format.CISCO
        else:
            return Format.UNKNOWN
    else:
        return Format.NONE


if __name__ == '__main__':
    macs = []
    mac_generator = MacLookup()
    args = parse_args()
    if args.debug:
        enable_debug_logging()
    if args.output:
        logger.info(f"Output file is {args.output}")
    else:
        logger.info(f"Couldn't retrieve output file, please specify one with --output")
        exit(-2)
    if args.generate:
        if args.quantity:
            logger.info(f"Generating {args.quantity} MAC addresses")
        else:
            logger.warning(f"Defaulting to generating 1 MAC address since --macs was not specified")
            args.quantity = 1
    if args.type:
        logger.info(f"Generating {args.type} MAC addresses")
    format_type = parse_type_argument(args.type)
    logger.debug(f"Format type is {format_type}")
    if args.generate:
        macs.extend(list(
            mac_generator.generate_n_mac_addresses(format_type=format_type, quantity=args.quantity, lowercase=False)))

    if args.validate:
        valid_macs = []
        if args.input:
            logger.info(f"Validating MAC addresses in file {args.input} ")
            macs.extend(load_macs_from_file(args.input))
            valid_macs = [x[1] for x in mac_generator.is_mac_addr_list_valid(macs) if x[0] ]
        elif args.generate:
            logger.info(f"Verifying MAC addresses generated")
            valid_macs = [x[1] for x in mac_generator.is_mac_addr_list_valid(macs) if x[0] ]
        else:
            logger.info(f"Couldn't retrieve input file, please specify one with --input")
            exit(-1)
        logger.info(valid_macs)
