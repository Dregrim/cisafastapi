from typing import Union
from fastapi import FastAPI, Query
import requests
import json
from datetime import datetime, timedelta

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/info")
def read_description():
    return {"Description": "This is FastAPI app that take data about CVE from NIST db",
            "Author":"Kulyhin Oleksandr"}

@app.get("/get/all")
def read_all():
    url = f"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"    
    response = requests.get(url)
    data = response.json()
    all_cve = {}
    for index, cve in enumerate(data['vulnerabilities']):
        # обмеження в кількості виведення результатів
        if index == 40:
            break
        all_cve.update({cve['cveID']:cve})

    return {"data": all_cve}

@app.get("/get/new")
def read_new():
    url = f"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"    
    response = requests.get(url)
    data = response.json()
    new_cve = {}
    for index, cve in enumerate(data['vulnerabilities']):
        # обмеження в кількості виведення результатів
        if index == 10:
            break
        new_cve.update({cve['cveID']:cve})

    return {"data": new_cve}

@app.get("/get/known")
def read_new():
    url = f"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    data = response.json()
    known_cve = {}
    for cve in data['vulnerabilities']:
        if cve["knownRansomwareCampaignUse"] == "Known":
            known_cve.update({cve['cveID']:cve})
        if len(known_cve) == 10:
            break

    return {"data": known_cve}

@app.get("/get/")
def read_key(query: str  = Query(...)):
    url = f"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url)
    data = response.json()
    matches = []
    for vulnerability in data.get("vulnerabilities", []):
        for k, value in vulnerability.items():
            if isinstance(value, str) and query.lower() in value.lower():
                matches.append(vulnerability)
                break
            elif isinstance(value, list):
                if any(query.lower() in str(item).lower() for item in value):
                    matches.append(vulnerability)
                    break

    return {"data": matches}