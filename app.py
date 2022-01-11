#!/usr/bin/python
# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IScannerListener
from burp import IExtensionStateListener
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from java.io import PrintWriter
from java.net import URL



# Fields within request to Auth Provider
# client_id
# redirect_uri
# response_type
# response_mode
# nonce
# state



OAuthUrlsIdentified = []

IMPLICIT_FLOW=0
CODE_FLOW=1
# Dict in the form oauth_mode[HOSTNAME]=FLOW
oauth_mode={}

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener):
    def registerExtenderCallbacks( self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        callbacks.setExtensionName("Burp OAuth2.0 Extender")
        
        # obtain our output and error streams
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        # register ourselves as a Proxy listener
        callbacks.registerProxyListener(self)

        # register ourselves as a custom scanner check
        #Commented out because it errored on running
        #callbacks.registerScannerCheck(self)
        
        # register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(self)

        self._helpers = callbacks.getHelpers()
        print(self._helpers)

    def extensionUnloaded(self):
        print "Extension was unloaded"

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Check if Message is a Response, and see what tool it came from. This is just helping with print formatting and tracking.
        #Check if Message is a Request and then check if it is coming from tool "Proxy".  If so, then analyze the request and go through thev parameters and see if any match known OAuth parameters. If so, Report.
        if messageIsRequest:
            if str(self._callbacks.getToolName(toolFlag)) == "Proxy":
                #print("Proxy is receiving a Request")
                analyzedRequest = self._helpers.analyzeRequest(messageInfo.getRequest())
                detectOAuth(messageInfo, analyzedRequest)
                    
        
        else:
            responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
            responseReceived = self._helpers.bytesToString(messageInfo.getResponse()).encode('utf-8')
            #print("responseInfo: ", responseInfo)
            #print("responseReceived: ", responseReceived)
            if str(self._callbacks.getToolName(toolFlag)) == "Extender":
                print("Extensions Response has been Received")
                
def detectOAuth(messageInfo, analyzedRequest):
    OAuthParameters = { "client_id": False,
                        "redirect_uri": False,
                        "response_type" : False,
                        "scope": False,
                        "state": False
                    }
    
    OAuthIdentified = False
    responseTypeIdentified = None
    #print ("Headers are: ", analyzedRequest.getHeaders())
    if analyzedRequest.getParameters():
        analyzedParameters = analyzedRequest.getParameters()
        for parameter in analyzedParameters:
            #print parameter.getName().lower()
            for OAuthParameter in OAuthParameters:
                #print "OauthParameter", OAuthParameter
                #print "Parameter", parameter.getName()
                if parameter.getName().lower()  == OAuthParameter:
                    #print "FOUND AN OAUTH PARAMETER", OAuthParameter
                    OAuthParameters[OAuthParameter] = True
                    if parameter.getName().lower() == "response_type":
                        responseTypeIdentified = parameter.getValue().lower()
                    
        if OAuthParameters["client_id"] and OAuthParameters["response_type"]:
            OAuthIdentified = True
            messageService = messageInfo.getHttpService()
            if str(messageService) not in str(OAuthUrlsIdentified):
                OAuthUrlsIdentified.append(messageService)
                print "------   New OAuth Identified   ------"
                print "URL observed was : " + messageService.getProtocol() + "://" + messageService.getHost() + " using Port : " + str(messageService.getPort())
                if responseTypeIdentified != None:
                    print "-- Authorization Code Type Detected as : " + responseTypeIdentified + " --"
                print " Parameters observed in the request indicating OAuth presence were :"
                for item, value in OAuthParameters.items():
                    if value == True:
                        print "     > " + item
                
            else:
                print "Existing OAuth Url Observed : " + messageService.getProtocol() + "://" + messageService.getHost()

def get_oauth_flow_mode(request):
    return
