#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from oletools.olevba3 import VBA_Parser


def get_result(filename):
    try:
        behavior = {}
        vbaparser = VBA_Parser(filename)
        if vbaparser.detect_vba_macros():
            results = vbaparser.analyze_macros()
            for item in results:
                details = re.sub(r"\(.*\)", "", str(item[2]))
                details = details.replace("strings", "str")
                details = re.sub(r" $", "", details)
                if item[0] == "AutoExec":
                    behavior.update({item[1]: details})
                if item[0] == "Suspicious":
                    behavior.update({item[1]: details})
            macro = vbaparser.reveal()
            attributes = re.findall(r"Attribute VB.*", macro, flags=re.MULTILINE)
            macro = re.sub(r"Attribute VB.*", "", macro)
            vbaparser.close()
            return {"behavior": behavior, "macro": macro, "attributes": attributes}
        return None
    except:
        return {}
