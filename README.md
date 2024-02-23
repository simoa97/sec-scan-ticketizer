
# Sec Scan Ticketizer

Security scan ticketizer is collection of scripts designed to streamline the vulnerability management process by automating the creation of JIRA tickets from the results of security scans performed with tools like Trivy or OWASP ZAP. 

This is a hobby project and still work in progress with planned future improvements.


## Documentation

### Setting up JIRA

#### Basic auth
This integration uses [Jira REST API v3](https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/#about). 
Current implementation uses Basic auth for [REST APIs](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/). 
For basic auth, API token is needed to authenticate the account. API token can be generated in following way [Atlassian Docs](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/):
- Log in to https://id.atlassian.com/manage-profile/security/api-tokens
- Click Create API token
- Enter a label for the API token
- Copy and save the API token (will be used as a secret in the pipeline)

The best practice would be to create a new “service account” a set up only the permissions that are needed for this workflow:
POST (create ticket) - Browse projects and Create issues [project permissions](https://confluence.atlassian.com/x/yodKLg) for the project in which the issue or subtask is created.
POST (search for tickets) - Browse projects [project permission](https://confluence.atlassian.com/x/yodKLg) for the project containing the issue. If issue-level security is configured, [issue-level security](https://confluence.atlassian.com/x/J4lKLg) permission to view the issue.

#### OAuth 2.0
tbd

### Python scripts

#### Trivy
Trivy script parses through json output of the performed scan. It has 2 input arguments - trivy_to_jira.py (scan result file) (account:apitoken).

#### OWASP ZAP
OWASP ZAP script parses through the terminal output of the scan. Unfortunately, when using the OWASP ZAP docker image, I could not make the flags for generating reports work. Thus, the script goes through the CLI/terminal output. For the use case, I stdout the OWASP ZAP output from the terminal to a file, and script then parses through the file.

Because I cannot generate the report, this script needs 3 input arguments - owasp_to_jira.py (scan result file) (account:apitoken) (targetname). The target name can be an image tag, as without it, there would be no indicator of the target of the scan which is very useful for the Jira ticket as the terminal output of OWASP ZAP doesn’t generate any data that would hint of scan target, making the Jira ticket harder to connect with the specific target (not impossible as description contains the URLs).

#### grype
tbd

### Setting up the API calls structure

#### POST (search for existing tickets)
All scripts use [Jira REST API POST method (Search for issues using JQL)](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/#api-rest-api-3-search-post) to search for already created tickets in Jira to prevent creation of duplicates. This call searches for the names of the tickets that should be created. If the script finds such ticket in Jira, it will not be created again.

Specify the organization url under the url variable in jira_search fucntion:
```python
url = "https://(your org name).atlassian.net/rest/api/3/search"
```

#### POST (create ticket)
All scripts use [Jira REST API POST method (Create issue)](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post) to create new tickets in Jira. This step is a little bit more complex than the previous POST method.
In my example I used brand new Jira and brand new Project in Jira. The setup will differentiate and will depend on how you want to have your tickets for vulnerabilities set up. I use the default issue type “Task”.

Specify the organization url under the url variable in jira_search fucntion:
```python
url = "https://(your org name).atlassian.net/rest/api/3/issue"
```

Every script has a function named jira_post_ticket. This function contains a variable named payload. This is the structure of the payload for the API call:

```python
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
}
```

This is the basic structure of the payload sufficient for creating a ticket with a title and description. Based on your needs, you can add more fields, modify the script and add other data to the ticket such as severity, custom fields, etc. To see a more complex structure, visit [Jira REST API POST method (Create issue)](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post), where on the right you can see code snippets for various programming languages.

Other than the ticket name and the description, to successfully configure the payload we need to obtain “issuetype” id and and “project” id. This can be done by: 
- Navigating into Jira project under which the tickets should be posted to
- Selecting the issuetype which will represent the ticket type of the vulnerabilities
  - To create new type see [Atlassian Documentation](https://support.atlassian.com/jira-cloud-administration/docs/add-edit-and-delete-an-issue-type/)
- Open the ticket with desired issue type
  - If there is not ticket with such issue type, create one manually and open it
- In the top right corner click on the three dots icon (⋯) and select Export XML
- In the XML:
  - “type id” is issuetype id
  - “project id” is project id
The XML export can be used to find other relevant fields you would like to include into your ticket.
 
After obtaining the relevant information, in this example issuetype id and project id, change these values in your scripts.

### Implementation into the pipeline (GitHub Actions)

For trivy see, simple trivy to jira [GitHub Action workflow](.github/workflows/trivy-to-jira.yml)
![trivy workflow](https://github.com/simoa97/sec-scan-ticketizer/actions/workflows/trivy-to-jira.yml/badge.svg)

For OWASP ZAP see, simple OWASP ZAP to jira [GitHub Action workflow](.github/workflows/owasp-zap-to-jira.yml)
![OWASP ZAP workflow](https://github.com/simoa97/sec-scan-ticketizer/actions/workflows/owasp-zap-to-jira.yml/badge.svg)

## Contributing

Contributions are always welcome! If you see any ways to improve, refactor or add new features, go for it.

See `contributing.md` **(tbd)** for ways to get started.


## License
Feel free to clone or download the scripts and use it, or use to code as inspiration for your own projects.
This repository is licensed under [MIT license](LICENSE).