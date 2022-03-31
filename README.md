# OAuth2.0 Extender for Burp Suite (Community and Pro)

## Description
OAuth2.0 Extender is a [Burp Suite](https://portswigger.net/burp/) extension to audit and pentest OAuth 2.0 flows. In a few words, OAuth2.0 Extender supports the following checks and funtionality:

- OAuth 2.0 grant type (Implicit or Authorization Code) being used
- Lack of security parameters/mechanisms (such as state and PKCE) during the OAuth 2.0 dance
- Access Tokens or Authorization Codes exchanged insecurily.
- Lack of validation around the state parameter, such as tampering and replay
- Lack of validation around the redirect_uri parameter, such as tampering and injection which could lead to open redirects or secrets leakage
- Open redirection and secrets leakage via redirect_uri parameter (Burp Suite Pro only)
- OAuth 2.0 grant types supported by the server
- [TODO] Redeem Access Tokens or Authorization Codes multiple times via requests replay
- [TODO] Incorrect implementation of the PKCE mechanism if implemented (tamper with 'code_challenge' parameter)
- [TODO] OAuth 2.0 secrets leakage via Referer Header
- [TODO] In case the OAuth 2.0 parameters' names do not follow the standard convention, allow the user to indicate the tool the naming convention for the parameters used
- [TODO] Allow user to provide own hostname/domain
- [TODO] OpenID checks support
- [TODO] Add tab to show Issues on Burp Community Edition

## Requirements
- [Jython](https://www.jython.org/download) >= 2.7.1

## Installation (Import function)

1. Clone this repository in your host:

    `git clone ...`

2. In Burp Suite, go to `Extender > Extensions` tab, click on the `Add` button, select Extension type `Python`  and load the `app.py` py file.

## Usage
OAuth 2.0 Extender listens to requests and responses going through the Burp Suite Proxy, and will automatically detect, audit and pentest an OAuth 2.0 dance.

However, if you missed an OAuth 2.0 process and want to test it, you can `Right click > Extensions > OAuth 2.0 Extender > Send to OAuth 2.0 Extender` your OAuth 2.0 requests which will be analyzed by the extension.

Finally, depending on your Burp version, discovered issues can be found in:

* Burp Professional: Dashboard tab -> Issues field
* Burp Community Edition: momentarily, you'll be able to find the issues in Extender tab -> Output tab for OAuth 2.0 Extender extension. To get extra information about the requests that were used to discover the issue, you can install the Logger++ extension to see them

### Screenshots
Right click > Extensions > OAuth 2.0 Extender > Send to OAuth 2.0 Extender :

[TODO] Add screenshots

## Reporting bugs and collaboration
- If you encountered a bug 🥴 and would like us to fix it, please use the GitHub [Bug Report](TODO) feature
- If you want to collaborate, please read the [CONTRIBUTING](./CONTRIBUTING.md) file. Also, feel free to reach out to any team member using your preferred mechanism
