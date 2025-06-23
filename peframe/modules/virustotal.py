#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests


def get_result(API_KEY, HASH, full=False):
    vt_url = f"https://www.virustotal.com/api/v3/files/{HASH}"
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    try:
        response = requests.get(vt_url, headers=headers, timeout=10)
        jsonResponse = response.json()
    except:
        return {"positives": "", "total": ""}
    if full:
        return jsonResponse
    if "error" not in jsonResponse:
        total = 0
        detections = jsonResponse["data"]["attributes"]["last_analysis_stats"]
        malicious = detections["malicious"]
        for result in (
            "harmless",
            "suspicious",
            "malicious",
            "undetected",
            "failure",
        ):
            total += detections[result]
        return {
            "positives": malicious,
            "total": total,
        }
    return jsonResponse
