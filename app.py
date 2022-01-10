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

newResponseRequest = '''GET / HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: 
Content-Type: application/json; charset=utf-8
Connection: close


'''

# Fields within request to Auth Provider
# client_id
# redirect_uri
# response_type
# response_mode
# nonce
# state

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
        callbacks.registerScannerCheck(self)
        
        # register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(self)

        self._helpers = callbacks.getHelpers()
        print(self._helpers)

    def extensionUnloaded(self):
        self._stdout.println("Extension was unloaded")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Check if Message is a Response, and see what tool it came from. This is just helping with print formatting and tracking.
        print("messageInfo: ", messageInfo)
        if messageIsRequest:
            if str(self._callbacks.getToolName(toolFlag)) == "Extender":
                print("Extension is making a Request")
            else:
                print("Incomimg Tool Flag = " + str(self._callbacks.getToolName(toolFlag)) + " Message is Request")
        
        else:
            responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
            responseReceived = self._helpers.bytesToString(messageInfo.getResponse()).encode('utf-8')
            print("responseInfo: ", responseInfo)
            print("responseReceived: ", responseReceived)
            if str(self._callbacks.getToolName(toolFlag)) == "Extender":
                print("Extensions Response has been Received")
            else:
                print("Incomimg Tool Flag = " + str(self._callbacks.getToolName(toolFlag)) + " Message is Response")
                
        # Check if Request and Check if Tool is Repeater or Scanner (Those are the tools we care about at the moment)
        # if not messageIsRequest and (str(self._callbacks.getToolName(toolFlag)) == "Repeater" or str(self._callbacks.getToolName(toolFlag)) == "Scanner"):
        #     print("We have a Response from a Tool we care about, Lets see if it meets the condition for testing")
        #     # Get our Responses some help
        #     responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
        #     responseReceived = self._helpers.bytesToString(messageInfo.getResponse()).encode('utf-8')
            
            
        #     # If response is 202 (Currenlty identified as being special circumstance for received response we want to look at)
        #     if responseInfo.getStatusCode() == 202:
        #         print("Response is 202, Envoking Extension Functionality.Generating a 2nd Request and Retieving its Response")
        #         # Build new Request to make (Get our Getter. This is also where we use our stored response payload)
        #         try:
        #             newResponseRequestBytes = self._helpers.stringToBytes(newResponseRequest)
        #             newResponse = self._callbacks.makeHttpRequest("westus.api.cognitive.microsoft.com", 443, True, newResponseRequestBytes)
        #             # Set new Response to our old response (Shortcutting the 2nd Order)
        #             messageInfo.setResponse(newResponse)
        #             print("Response Received and Original Call has been Changed (Successful Extension Call)")
        #         except:
        #             # Something Happend With the Code, So we just moved on.
        #             print("Exception Raised, Extension Functionaliity Cancelled")
        #     else:
        #         # Response did not meet condition, so we move on.
        #         print("Non 202 Status Code Received " + str(responseInfo.getStatusCode()))

def get_oauth_flow_mode(request):
    return
