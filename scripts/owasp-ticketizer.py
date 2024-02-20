import re
import json
import sys
import requests
import argparse
from requests.auth import HTTPBasicAuth


# This call only takes a limited amount of characters for the jql query
# Could a problem with long ticket names, if problem occurs use the POST method
# https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/#api-rest-api-3-search-post
def jira_search(ticket_name, token):
    """API call for searching issues in JIRA by name"""
    url = "https://adamsimo.atlassian.net/rest/api/3/search"

    split_token = token.split(':')
    usr = split_token[0]
    tok = split_token[1]

    auth = HTTPBasicAuth(usr, tok)

    headers = {
        "Accept": "application/json"
    }

    query = {
        'jql': f'summary ~ "{ticket_name}"'
    }

    response = requests.request(
        "GET",
        url,
        headers=headers,
        params=query,
        auth=auth
    )
    # save response as a dictionary
    response_dict = json.loads(response.text)

    # return the total of the matched tickets

    # doesnt work with long queries - needs to be changed to POST method
    try:
        return response_dict['total']
    except KeyError:
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


# Input argument for the CLI
parser = argparse.ArgumentParser()

parser.add_argument('scanresults', help="""OWASP ZAP output of the security
                    scan in a text file format.""")
parser.add_argument('apitoken', help='Secret in form of username:api_token.')
parser.add_argument('targetname', help="""Name of the scanned target. As OWASP
                    zap scan result do not contain the name of the target.""")

args = parser.parse_args()

f = args.scanresults
t = args.apitoken
n = args.targetname

# open the file
while True:
    try:
        with open(f, 'r',) as file:
            data = file.readlines()
        break
    except FileNotFoundError:
        print(f'Error: The file "{f}" was not found. Please provide a valid file name.')
        sys.exit(1)

finding_check = False  # check state to make sure there were findings in the output of the scan

for i, l in enumerate(data):
    if l.startswith('WARN-NEW') or l.startswith('WARN-INPROG'):  # find lines which start with the finding
        input_warn = l.rstrip()
        slice_index = input_warn.find('[')
        warn_name = f"{input_warn[:slice_index].strip()} ({n})"  # save the warning name
        vuln_match = re.search(r'\[(\d+)]', l)  # search for the vulnerability number
        addr_match = re.search(r'x (\d+)', l)  # search for the count of vulnerable addresses
        vuln_number = int(vuln_match.group(1)) if vuln_match else None  # save the vulnerability number
        addr_count = int(addr_match.group(1)) if addr_match else None  # save the count of vulnerable addresses
        owasp_ref = f' https://www.zaproxy.org/docs/alerts/{str(vuln_number)}'  # create a owasp db reference
        if addr_count is not None:  # save the next lines containing vulnerable
            # addresses 
            addr_lines = data[i+1:i+(addr_count + 1)]
        else:
            continue
        addr_list = ''.join(addr_lines)
        issue_description = f"""Vulnerability name: OWASP - {warn_name}
OWASP Reference docs: {owasp_ref.lstrip()} 
Vulnerable addresses:
{addr_list}"""
        finding_check = True
        if finding_check is True:
            if jira_search(warn_name, t) != 0:
                print(f'{warn_name} already exists in JIRA.')
            else:
                jira_post_ticket(warn_name, issue_description, t)
                print(f'{warn_name} was created in JIRA.')
if not finding_check:
    print(f'There are no vulnerabilities that can be posted to JIRA found in {n}, or input file is not in the right format.')
