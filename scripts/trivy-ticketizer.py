import json
import collections
import sys
import requests
import argparse
from requests.auth import HTTPBasicAuth


def jira_search(ticket_name, token):
    """API call for searching issues in JIRA by name"""
    url = "https://adamsimo.atlassian.net/rest/api/3/search"

    split_token = token.split(':')
    usr = split_token[0]
    tok = split_token[1]

    auth = HTTPBasicAuth(usr, tok)

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    payload = json.dumps({
        "expand": [
            "names"
        ],
        "fields": [
            "summary"
        ],
        "fieldsByKeys": "false",
        "jql": f'summary ~ "{ticket_name}"',
        "maxResults": 15,
        "startAt": 0
    })

    response = requests.request(
        "POST",
        url,
        data=payload,
        headers=headers,
        auth=auth
    )
    # save response as a dictionary
    response_dict = json.loads(response.text)

    # return the total of the matched tickets
    return response_dict.get('total')


def jira_post_ticket(ticket_title, ticket_description, token):
    """API to post vulnerabilities as issues in JIRA"""
    url = "https://adamsimo.atlassian.net/rest/api/3/issue"

    split_token = token.split(':')
    usr = split_token[0]
    tok = split_token[1]

    auth = HTTPBasicAuth(usr, tok)

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    # https://community.atlassian.com/t5/Jira-Software-questions/Getting-Error-quot-Operation-value-must-be-an-Atlassian-Document/qaq-p/1304733
    payload = json.dumps({
        "fields": {
            "summary": f"{ticket_title}",
            "issuetype": {
                "id": "10001"
            },
            "project": {
                "id": "10000"
            },
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": f"{ticket_description}"
                            }
                         ]
                    }
                ]
            }
        }
    })

    requests.request(
        "POST",
        url,
        data=payload,
        headers=headers,
        auth=auth
    )


# Input argument parser for CLU
parser = argparse.ArgumentParser()

parser.add_argument('scanresults', help='Trivy output of the security scan in a json format.')
parser.add_argument('apitoken', help='Secret in form of username:api_token.')

args = parser.parse_args()

f = args.scanresults
t = args.apitoken

# open the file
while True:
    try:
        with open(f, 'r',) as j:
            testfile = json.load(j)
        break
    except FileNotFoundError:
        print(f'Error: The file "{f}" was not found. Please provide a valid file name.')
        sys.exit(1)
    except json.decoder.JSONDecodeError:
        print(f'Format of the file "{f}" is not JSON.')
        sys.exit(1)


only_results = testfile  # save the file into a variable

scan_artifact_name = testfile['ArtifactName']  # name of the scanned image

for result in only_results['Results']:  # for every key in the Results dictionary
    scan_target = result['Target']
    scan_target_class = result['Class']
    ticket_name = (f'{scan_artifact_name} - {scan_target} - {scan_target_class}')

    # split dict into several lists, inspired by
    # https://stackoverflow.com/questions/4091680/splitting-a-list-of-dictionaries-into-several-lists-of-dictionaries
    results = collections.defaultdict(list)  # create dictionary with default values of empty lists
    try:
        for vulnerabilities in result['Vulnerabilities']:  # for every list in the dictionary
            results[vulnerabilities['VulnerabilityID']].append(vulnerabilities)  # append to the results
        results_list = result.get('Vulnerabilities', [])
        wrapped_results_list = [[vulnerability] for vulnerability in results_list]  # wrap each dictionary into a separate list

        for x in wrapped_results_list:  # list of (list of details of) per vulnerability
            for vuln in x:  # for each list of details for vulnerability
                cve_severity = vuln['Severity']
                vuln_issue_title = f"""({cve_severity}) {vuln['VulnerabilityID']}: {scan_artifact_name}"""
                vuln_issue_description = f"""Vulnerability ID:  {vuln['VulnerabilityID']}, {vuln['PrimaryURL']}
Target: {scan_target}, class: {scan_target_class}
Package ID: {vuln["PkgName"]} version: {vuln['InstalledVersion']}
Status : {vuln["Status"]}, fixed version: {vuln["FixedVersion"]}

Title: {vuln['Title']}
Description: {vuln['Description']}
Severity: {vuln['Severity']}"""
            if jira_search(vuln_issue_title, t) != 0:
                print(f'{vuln_issue_title} already exists in JIRA.')
            else:
                jira_post_ticket(vuln_issue_title, vuln_issue_description, t)
                print(f'{vuln_issue_title} was created in JIRA.')
    except KeyError:
        print(f'There are no vulnerabilities that can be posted to JIRA found in {scan_target}.')
