#!/usr/bin/python
# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IScannerListener
from burp import IExtensionStateListener
from burp import IContextMenuFactory 
from burp import IScanIssue

from java.io import PrintWriter
from java.util import ArrayList
from javax.swing import JMenuItem

import sys


# response_type=code vs response_type=id_token or response_type=token . Guess it will change from host to host? We should therefore use a sort of heuristic?

oauth_urls_identified=[]

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
                self.detect_oauth(messageInfo)
            else:
                print("WARNING: got message from unidentified tool")
        
        else:
            responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
            responseReceived = self._helpers.bytesToString(messageInfo.getResponse()).encode('utf-8')
            #print("responseInfo: ", responseInfo)
            #print("responseReceived: ", responseReceived)
            if str(self._callbacks.getToolName(toolFlag)) == "Extender":
                print("Extensions Response has been Received")
                
    def detect_oauth(self, message_info):
        analyzed_request= self._helpers.analyzeRequest(message_info.getRequest())
        oauth_parameters = { "client_id": False,
                            "response_type" : False,
                            "redirect_uri": False,
                            "scope": False, 
                            "state": False 
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
                message_service = message_info.getHttpService()
                if str(message_service) not in oauth_urls_identified:
                    oauth_urls_identified.append(str(message_service))
                    print("------   New OAuth Identified   ------")
                    print("URL observed was : " + str(message_info.getUrl()))
                    if response_type_identified:
                        print("-- Authorization Type Detected as : " + response_type_identified + " --")
                    print(" Parameters observed in the request indicating OAuth presence were:")
                    for item, value in oauth_parameters.items():
                        if value == True:
                            print("     > " + item)
                    try:
                        self.start_security_checks(message_info, analyzed_request, response_type_identified)
                    except:
                        print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])
                        
                else:
                    print("Existing OAuth Url Observed : " + str(message_info.getUrl()))

    def start_security_checks(self, message_info, analyzed_request, response_type):
        message_service = message_info.getHttpService()
        print("Starting security checks:")
        if "token" in response_type:
            issue=CustomScanIssue(   
                                message_service, 
                                message_info.getUrl(),
                                [message_info], 
                                "Using OAuth Implicit Mode",
                                "TODO Detail",
                                "Medium",
                                "Certain",
                                "TODO Remediation"
                                )
            print("New issue: " + issue.getIssueName())
            self._callbacks.addScanIssue(issue)
            
        elif "code" in response_type:
            return
        else: 
            print("'response_type' not recognized. Please contact support")
        return


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence, remediation_detail):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence= confidence
        self._remediation_detail= remediation_detail

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