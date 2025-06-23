#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from . import stringstat


def valid_ip(address):
    try:
        host_bytes = address.split(".")
        valid = [int(b) for b in host_bytes]
        valid = [b for b in valid if 0 <= b <= 255]
        return len(host_bytes) == 4 and len(valid) == 4
    except:
        return False


def get_result(filename, strings_match):
    strings_list = []
    ip_list = []
    file_list = []
    filetype_dict = {}
    url_list = []
    fuzzing_dict = {}

    strings_list = list(stringstat.get_result(filename))

    # Get filetype and fuzzing
    file_type = strings_match["filetype"].items()
    fuzzing_list = strings_match["fuzzing"].items()

    # Strings analysis
    for str_val in strings_list:
        str_val = str_val.rstrip()
        if len(str_val) < 2000:
            # URL list
            urllist = re.findall(
                r"((smb|srm|ssh|ftps?|file|sftp|https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)",
                str_val,
                re.MULTILINE,
            )
            if urllist:
                for url in urllist:
                    url_list.append(re.sub(r"\(|\)|;|,|\$", "", url[0]))

            # IP list
            iplist = re.findall(r"[0-9]+(?:\.[0-9]+){3}", str_val, re.MULTILINE)
            if iplist:
                for ip in iplist:
                    if valid_ip(str(ip)) and not re.findall(
                        r"[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}\.0", str(ip)
                    ):
                        ip_list.append(str(ip))

            # FILE list
            file_pattern = r"(?<!\S)((?:[\w\-.\\/\[\]]{1,255}[\\/])*(?:[\w\[\]\-{}]+)?\.(?P<ext>[a-z0-9]{2,4}))(?!\S)"
            fname = re.findall(
                file_pattern,
                str_val,
                re.IGNORECASE | re.MULTILINE,
            )
            if fname:
                for word in fname:
                    if len(word[0]) > 5:
                        file_list.append(word[0])

    # Purge list
    ip_list = list(set(ip_list))
    url_list = list(set(url_list))

    # Search for valid filename
    filetype_dict = {}
    array_tmp = []
    for file in file_list:
        for key, value in file_type:
            for ext in value:
                match = re.findall(
                    "\\" + ext + "$", str(file), re.IGNORECASE | re.MULTILINE
                )
                if match and file.lower() not in array_tmp and len(file) > 4:
                    filetype_dict.update({file: key})
                    array_tmp.append(file.lower())
        if file.lower() not in array_tmp:
            filetype_dict.update({file: "Unknown"})
            
    # Initialize fuzzing
    for key, value in fuzzing_list:
        fuzzing_dict[key] = []

    # Strings analysis for fuzzing
    array_tmp = []
    for str_val in strings_list:
        if len(str_val) < 256:
            for key, value in fuzzing_list:
                fuzz_match = re.findall(value, str_val, re.IGNORECASE | re.MULTILINE)
                if fuzz_match and str_val.lower() not in array_tmp:
                    fuzzing_dict[key].append(str_val)
                    array_tmp.append(str_val.lower())

    # Remove empty key fuzzing
    for key, value in fuzzing_list:
        if not fuzzing_dict[key]:
            del fuzzing_dict[key]

    return {
        "file": filetype_dict,
        "url": url_list,
        "ip": ip_list,
        "fuzzing": fuzzing_dict,
        "dump": strings_list,
    }
