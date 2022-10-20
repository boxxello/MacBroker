
<div align="center">

# MacBroker


A simple module to generate valid mac addresses and to validate inputted ones

<a href="https://github.com/boxxello/MacGenerator-Validator/commits/main">
  <img src="https://img.shields.io/github/contributors/boxxello/MacGenerator-Validator?color=teal&style=for-the-badge">
</a>
<a href="https://github.com/boxxello/MacGenerator-Validator/graphs/contributors">
  <img src="https://img.shields.io/github/last-commit/boxxello/MacGenerator-Validator?style=for-the-badge">
</a>
</div>
<br>

 
# Installation
--------------

```
pip install git@github.com:boxxello/MacGenerator-Validator.git
```

## MacBroker Hello World

```python
from macbroker.Generator import MacBroker, Format

mac_generator=MacBroker()
print(MacBroker().lookup("60:8B:0E:00:00"))
print(mac_generator.generate_n_mac_addresses(format_type=Format.CISCO, quantity=3, lowercase=False))
print(mac_generator.generate_n_mac_addresses(format_type=Format.COLON, quantity=3, lowercase=True))
```
Output:

>  Apple, Inc.

>  ['0016.8D26.BF46', 'F8C3.9755.3DEE', '2CC4.0740.87B0']

>  ['00:25:15:3e:dd:be', 'ec:30:91:0f:90:46', '98:52:3d:77:7e:cc']

# Supported formats
--------------
There are multiple formats available such as:
<br>
Format      | Output
------------- | -------------
Cisco         | MMMM.MMSS.SSSS 
Colon         | MM:MM:MM:SS:SS:SS
Hyphen        | MM-MM-MM-SS-SS-SS
Period        | MM.MM.MM.SS.SS.SS
None          | MMMMMMSSSSSS



# Update the vendor list

This module caches a list of 
- Vendors
- Prefixes
- Nationalities
related to MAC addresses directly from the IEEE at run-time.
<br>
If ever needed to update information you can download a fresh the following code.

```python
from macbroker.Generator import MacBroker

MacBroker().update_vendors()
```

or you can also check the latest update date and update it if needed with the following:
```python
from macbroker.Exceptions import NoDateFoundCacheError
from macbroker.Generator import MacBroke

try:
    days=mac_generator.get_last_updated_cache_in_days()
except NoDateFoundCacheError:
    pass
else:
    if days > 30:
        print("Updating cache")
        mac_generator.update_vendors()
```

There is also an asynchronous interface, so you can also use:
```python
import asyncio
from macbroker.Generator import  Format, AsyncMacBroker

async def main():
    mac_generator=AsyncMacBroker()
    print(await mac_generator.generate_n_mac_addresses(format_type=Format.CISCO, quantity=3, lowercase=False))
    print(await mac_generator.generate_n_mac_addresses(format_type=Format.PERIOD, quantity=3, lowercase=True))
    print(await mac_generator.lookup("60:8B:0E:00:00"))
    print(await mac_generator.look_up_nationality("60:8B:0E:00:00"))
loop = asyncio.get_event_loop()
loop.run_until_complete(main())

```

Output:

>  ['70DD.A17C.6758', 'F021.9DDF.A16A', 'C4AD.34AF.30B8']

> ['3c.7a.c4.61.7f.87', '00.08.a0.54.b9.af', 'f4.c7.95.51.0c.40']

>  Apple, Inc.

>  SZ
 
# Command line interface

The command line interface could be improved but right now it provides support for: 
- validating mac addresses from an input list with --input or -i and --validate or -v
- outputting the validated mac addresses to an output file with --output or -o
- generating mac addresses with --generate or -g and specifying the quantity with --quantity or -q
- generating mac addresses with a specific format with --format or -f
- activating the debug logger with --debug or -d


The cli can be used as follows:
```bash
$ macbroker args
```
or
```bash
$ python -m macbroker args
```

The arguments are described above and the help can be accessed with:
```bash
[-h,--help] [-i,--input INPUT]
[-o,--output OUTPUT] [-v,--validate]
[-g,--generate] [-q,--quantity QUANTITY]
[-f,--format {cisco,colon,hyphen,period,none}] [-d,--debug]
[-o, --output OUTPUT]
```

More to come in the future.

License
-------------

Licensed under the Apache License, Version 2.0


Thanks goes to these existing libraries
-------------
-   This product include portions of code from [mac_vendor_lookup](https://github.com/bauerj/mac_vendor_lookup)

Contributing
-------------

-   Fork it: <https://github.com/boxxello/MacGenerator-Validator/fork>
-   Create your feature branch: `git checkout -b MY-NEW-FEATURE`
-   Commit your changes: `git commit -am 'Add some feature'`
-   Push to the branch: `git push origin MY-NEW-FEATURE`
-   Submit a pull request, they are always appreciated!
