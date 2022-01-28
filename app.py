#!/usr/bin/python
# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IScannerListener
from burp import IExtensionStateListener
from burp import IContextMenuFactory 
from burp import IScanIssue
from burp import IParameter

from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem

import sys
import json


f = open('issues_documentation.json')
issues_documentation = json.load(f)

# response_type=code vs response_type=id_token or response_type=token . Guess it will change from host to host? We should therefore use a sort of heuristic?

oauth_urls_identified=dict()

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        self._callbacks.setExtensionName("OAuth2.0 Extender")
        
        # obtain our output and error streams
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # register ourselves as an HTTP listener
        self._callbacks.registerHttpListener(self)
        
        # register ourselves as a Proxy listener
        self._callbacks.registerProxyListener(self)

        # register ourselves as a custom scanner check
        #Commented out because it errored on running
        #callbacks.registerScannerCheck(self)
        
        # register ourselves as an extension state listener
        self._callbacks.registerExtensionStateListener(self)
        self._callbacks.registerContextMenuFactory(self)

        self._helpers = self._callbacks.getHelpers()
        
        print("OAuth2.0 Extender was loaded successfully")

    def extensionUnloaded(self):
        print("OAuth2.0 Extender unloaded successfully")
    
    def createMenuItems(self, invocation):
        self._context = invocation
        menuList = ArrayList()

        invocation_allowed = [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_PROXY_HISTORY,
                              invocation.CONTEXT_TARGET_SITE_MAP_TABLE, invocation.CONTEXT_TARGET_SITE_MAP_TREE,
                              invocation.CONTEXT_MESSAGE_VIEWER_REQUEST, invocation.CONTEXT_INTRUDER_ATTACK_RESULTS, 
                              invocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS, invocation.CONTEXT_SCANNER_RESULTS, 
                              invocation.CONTEXT_SEARCH_RESULTS]

        # TODO should we allow the user to send multiple messages?
        if self._context.getInvocationContext() in invocation_allowed and len(self._context.selectedMessages) == 1:
            parentMenu = JMenuItem('Send to OAuth2.0 Extender', actionPerformed=self.MenuAction)
            menuList.add(parentMenu)

        # TODO delete this
        # Request info
        # iRequestInfo = self._helpers.analyzeRequest(self._context.getSelectedMessages()[0])
        # self.setData(iRequestInfo)

        return menuList

    def MenuAction(self, event):
        
        messageInfo = self._context.getSelectedMessages()[0]
        self.detect_oauth(messageInfo)


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Check if Message is a Response, and see what tool it came from. This is just helping with print formatting and tracking.
        #Check if Message is a Request and then check if it is coming from tool "Proxy".  If so, then analyze the request and go through thev parameters and see if any match known OAuth parameters. If so, Report.
        if messageIsRequest:
            if str(self._callbacks.getToolName(toolFlag)) == "Proxy":
                #print("Proxy is receiving a Request")
                analyzedRequest = self._helpers.analyzeRequest(messageInfo.getRequest())
                try:
                    self.detect_oauth(messageInfo)
                except:
                    print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])
            else:
                print("WARNING: got message from unidentified tool", str(self._callbacks.getToolName(toolFlag)))
        
        else:
            responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
            responseReceived = self._helpers.bytesToString(messageInfo.getResponse()).encode('utf-8')
            #print("responseInfo: ", responseInfo)
            #print("responseReceived: ", responseReceived)
            if str(self._callbacks.getToolName(toolFlag)) == "Extender":
                print("Extensions Response has been Received")
                
    def detect_oauth(self, message_info):
        analyzed_request= self._helpers.analyzeRequest(message_info.getRequest())
        message_service = message_info.getHttpService()
        global latest_oauth_server
        oauth_parameters = { "client_id": False,
                            "response_type" : False,
                            "redirect_uri": False,
                            "scope": False, 
                            "state": False,
                            "nonce": False,
                            "code_challenge": False,
                            "code_challenge_method": False
                            }
        
        oauth_identified = False # TODO will this be used?
        response_type_identified = None
        #print ("Headers are: ", analyzed_request.getHeaders())
        if analyzed_request.getParameters():
            analyzed_parameters = analyzed_request.getParameters()
            for parameter in analyzed_parameters:
                #print parameter.getName().lower()
                for oauth_parameter in oauth_parameters:
                    #print "oauth_parameter", oauth_parameter
                    #print "Parameter", parameter.getName()
                    if parameter.getName().lower()  == oauth_parameter:
                        #print "FOUND AN OAUTH PARAMETER", oauth_parameter
                        oauth_parameters[oauth_parameter] = True
                        if parameter.getName().lower() == "response_type":
                            response_type_identified = parameter.getValue().lower()
                        
            if oauth_parameters["client_id"] and oauth_parameters["response_type"]:
                oauth_identified = True
                print("HTTP service: ", str(message_service)) #Delete this print
                if str(message_service) not in oauth_urls_identified:
                    oauth_urls_identified[str(message_service)]=[str(response_type_identified)]
                    print("------   New OAuth Identified   ------")
                    print("URL observed was : " + str(message_info.getUrl()))
                    print(" Parameters observed in the request indicating OAuth presence were:")
                    for item, value in oauth_parameters.items():
                        if value == True:
                            print("     > " + item)
                    if response_type_identified:
                        print("-- Authorization Type Detected as : " + response_type_identified + " --")
                        latest_oauth_server=str(message_service)
                        self.start_security_checks(message_info, analyzed_request, response_type_identified, analyzed_parameters, oauth_parameters )

                    
                elif str(response_type_identified) not in oauth_urls_identified[str(message_service)]:
                    oauth_urls_identified[str(message_service)].append([str(response_type_identified)])
                    print("------   Existing OAuth With Different Flow Identified   ------")
                    print("URL observed was : " + str(message_info.getUrl()))
                    print(" Parameters observed in the request indicating OAuth presence were:")
                    for item, value in oauth_parameters.items():
                        if value == True:
                            print("     > " + item)
                    if response_type_identified:
                        print("-- Authorization Type Detected as : " + response_type_identified + " --")
                        latest_oauth_server=str(message_service)
                        self.start_security_checks(message_info, analyzed_request, response_type_identified, analyzed_parameters, oauth_parameters )
                
                else:
                    print("Existing OAuth Url Observed: " + str(message_service) + " (" + str(message_info.getUrl()) + ")")
        
            else:
                self.start_security_checks(message_info, analyzed_request, None, analyzed_parameters, oauth_parameters)

    def start_security_checks(self, message_info, analyzed_request, response_type, analyzed_parameters, oauth_parameters):
        message_service = message_info.getHttpService()
        print("Starting security checks:")
        #Start Check if Implicit Mode by "Token" in response_type or Authorizaiton Code Mode by "code" in response_type
        if response_type and ("token" or "code" in response_type):
            if "token" in response_type:
                self.create_new_issue("using_implicit_mode",message_service,message_info.getUrl(),[message_info])

            else: #"code" is in response_type indicating Authorization Code Mode
                self.create_new_issue("using_code_mode",message_service,message_info.getUrl(),[message_info])
                
                if oauth_parameters["code_challenge"] or oauth_parameters["code_challenge_method"] == False:
                    self.create_new_issue("code_mode_without_PKCE",message_service,message_info.getUrl(),[message_info])
                
            if oauth_parameters["state"] == False:
                print("No, Value: 'State'  does not exist in dictionary")
                print ("Response Type 'Implicit Grant' Detected without State Paremeter")
                self.create_new_issue("implicit_mode_without_state",message_service,message_info.getUrl(),[message_info])

                if oauth_parameters["nonce"] == False:
                    print("No, Value: 'Nonce'  does not exist in dictionary")
                    print ("Response Type 'Implicit Grant' Detected without Nonce Paremeter")
                    self.create_new_issue("implicit_mode_without_nonce",message_service,message_info.getUrl(),[message_info])
                
        elif response_type: 
            print("'response_type' " + response_type + "not recognized. Please contact support")
        
        elif response_type is None:
            analyzed_parameters = analyzed_request.getParameters()
            global latest_oauth_server
            if analyzed_parameters and latest_oauth_server:                
                for response_type in oauth_urls_identified[latest_oauth_server]:
                    if 'token' in response_type:  
                        for parameter in analyzed_parameters:   
                            if "token" in parameter.getName().lower() and parameter.getType()==IParameter.PARAM_URL: 
                                self.create_new_issue("access_token_as_URL_parameter", message_service,message_info.getUrl(),[message_info])
                                
                    elif 'code' in response_type:
                        for parameter in analyzed_parameters:
                            if "code" in parameter.getName().lower() and parameter.getType()==IParameter.PARAM_URL: 
                                self.create_new_issue("access_code_as_URL_parameter",message_service,message_info.getUrl(),[message_info])
                                
        return
    
    def create_new_issue(self, message_service, url, message_info_list, issue_id):
        issue=CustomScanIssue(   
                            message_service, 
                            url,
                            message_info_list, 
                            issue_id
                            )
        print("New issue: " + issue.getIssueName())
        self._callbacks.addScanIssue(issue)

class CustomScanIssue(IScanIssue):
    def __init__(self, issue_id, httpService, url, httpMessages):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        
        global issues_documentation
        issue_documentation=issues_documentation[issue_id]
        self._name = issue_documentation["name"]
        self._detail = issue_documentation["detail"]
        self._severity = issue_documentation["severity"]
        self._confidence= issue_documentation["confidence"]
        self._remediation_detail= issue_documentation["remediation_detail"]

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation_detail

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
        
