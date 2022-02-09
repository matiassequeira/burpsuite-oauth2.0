#!/usr/bin/python
# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IHttpListener
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
import random
import string
from thread import start_new_thread
from urlparse import urlparse
import time

f = open('issues_documentation.json')
issues_documentation = json.load(f)

# response_type=code vs response_type=id_token or response_type=token . Guess it will change from host to host? We should therefore use a sort of heuristic?

oauth_urls_identified=dict()
latest_oauth_server=None

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener, IContextMenuFactory):
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

        # register ourselves as a custom scanner check
        #Commented out because it errored on running
        #callbacks.registerScannerCheck(self)
        
        # register ourselves as an extension state listener
        self._callbacks.registerExtensionStateListener(self)
        self._callbacks.registerContextMenuFactory(self)

        self._helpers = self._callbacks.getHelpers()

        self._collaborator = self._callbacks.createBurpCollaboratorClientContext()
        
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
        #  if you want the request before leaving Burp or if you want to capture the request after it gets a response. For that, you have the Boolean messageIsRequest—a setting of true will capture the request before leaving, and false will capture it with a response.
        #Check if Message is a Request and then check if it is coming from tool "Proxy".  If so, then analyze the request and go through thev parameters and see if any match known OAuth parameters. If so, Report.
        if not messageIsRequest:
            if str(self._callbacks.getToolName(toolFlag)) == "Proxy":
                #print("Proxy is receiving a Request")
                analyzedRequest = self._helpers.analyzeRequest(messageInfo.getRequest())
                try:
                    self.detect_oauth(messageInfo)
                except:
                    print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])
            else:
                print("WARNING: got message from unidentified tool: " + str(self._callbacks.getToolName(toolFlag)))
                print(self._helpers.bytesToString(messageInfo.getRequest()).encode('utf-8'))
              
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
                
            if not oauth_parameters["state"]:
                print ("Response Type 'Implicit Grant' Detected without State Paremeter")
                self.create_new_issue("implicit_mode_without_state",message_service,message_info.getUrl(),[message_info])

            if not oauth_parameters["nonce"]:
                print("No, Value: 'Nonce'  does not exist in dictionary")
                print ("Response Type 'Implicit Grant' Detected without Nonce Paremeter")
                self.create_new_issue("implicit_mode_without_nonce",message_service,message_info.getUrl(),[message_info])
            
            if oauth_parameters["redirect_uri"]:
                self.redirect_uri_checks(message_info)
            else:
                start_new_thread(self.inject_redirect_uri, (message_info,False,))
                
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
                
                
                if contains_parameters(analyzed_parameters, ["token", "code"]):
                    if contains_parameters(analyzed_parameters, ["state"]):
                        print("Tampering State parameter..")
                        self.state_parameter_checks(message_info)
                                
        return
    
    def create_new_issue(self, issue_id, message_service, url, message_info_list, details=None):
        issue=CustomScanIssue(   
                            issue_id,
                            message_service, 
                            url,
                            message_info_list, 
                            details
                            )
        print("New issue: " + issue.getIssueName())
        self._callbacks.addScanIssue(issue)
    

    def redirect_uri_checks(self, message_info):
        analyzed_request= self._helpers.analyzeRequest(message_info.getRequest())
        analyzed_parameters = analyzed_request.getParameters()

        for parameter in analyzed_parameters:
            if 'redirect' in parameter.getName().lower():
                start_new_thread(self.tamper_redirect_uri_with_subdomain, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_path_traversal, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_collab_domain, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_top_level_domain, (message_info, parameter,))
                start_new_thread(self.inject_redirect_uri, (message_info, True,))
                start_new_thread(self.tamper_redirect_uri_with_localhost_in_collab_domain, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_parsing_discrepancies, (message_info, parameter,))
                break
        return


    def tamper_redirect_uri_with_subdomain(self,message_info, parameter):
        try:    
            param_value= parameter.getValue()
            
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==decoded_url else False

            parsed_url= urlparse(decoded_url)
            parsed_url= parsed_url._replace(netloc='test-subdomain.'+parsed_url.netloc)
            
            new_param_value=parsed_url.geturl()
            if is_url_encoded:
                new_param_value= self._helpers.urlEncode(new_param_value)

            self.send_request_and_fire_alert(message_info, parameter, new_param_value, "subdomain_allowed_in_redirect_uri")
        except:
            print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])


    def tamper_redirect_uri_with_path_traversal(self,message_info, parameter):
        try:    
            param_value= parameter.getValue()
            
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==decoded_url else False

            parsed_url= urlparse(decoded_url)
            parsed_url= parsed_url._replace(path= parsed_url.path + '../')
            
            new_param_value=parsed_url.geturl()
            if is_url_encoded:
                new_param_value= self._helpers.urlEncode(new_param_value)

            self.send_request_and_fire_alert(message_info, parameter, new_param_value, "directory_traversal_in_redirect_uri")
        except:
            print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])

    
    def tamper_redirect_uri_with_collab_domain(self, message_info, parameter):
        try:
            param_value= parameter.getValue()
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==decoded_url else False

            payload=self._collaborator.generatePayload(False)
            new_param_value= 'https://'+payload
            if is_url_encoded:
                new_param_value= self._helpers.urlEncode(new_param_value)

            modified_message_info= self.send_request_and_fire_alert(message_info, parameter, new_param_value, "tampered_redirect_uri")

            # Wait a prudent time to see if any request was issued to the collab payload
            time.sleep(60)
            collab_interactions= self._collaborator.fetchCollaboratorInteractionsFor(payload)
            if collab_interactions:
                details= get_collabs_interactions_summary(collab_interactions)
                self.create_new_issue('tampered_redirect_uri_with_redirection', message_info.getHttpService(),message_info.getUrl(),[message_info,modified_message_info], details)
        except:
            print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])


    def tamper_redirect_uri_with_top_level_domain(self, message_info, parameter):
        try:    
            param_value= parameter.getValue()
            
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==decoded_url else False

            parsed_url= urlparse(decoded_url)
            parsed_url= parsed_url._replace(path= '')
            
            new_param_value=parsed_url.geturl()
            if is_url_encoded:
                new_param_value= self._helpers.urlEncode(new_param_value)

            self.send_request_and_fire_alert(message_info, parameter, new_param_value, "top_level_domain_allowed_in_redirect_uri")
        except:
            print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])


    def inject_redirect_uri(self, message_info, redirect_uri_is_present):
        try:
            payload=self._collaborator.generatePayload(False)
            new_param_value= 'https://'+payload
            new_param_value= self._helpers.urlEncode(new_param_value)

            new_param= self._helpers.buildParameter('redirect_uri', new_param_value, IParameter.PARAM_URL)

            if redirect_uri_is_present:
                modified_message_info= self.send_request_and_fire_alert(message_info, new_param, None, "polluted_redirect_uri_allowed")
            else:
                modified_message_info= self.send_request_and_fire_alert(message_info, new_param, None, "injected_redirect_uri_allowed")

            # Wait a prudent time to see if any request was issued to the collab payload
            time.sleep(60)
            collab_interactions= self._collaborator.fetchCollaboratorInteractionsFor(payload)
            if collab_interactions:
                details= get_collabs_interactions_summary(collab_interactions)
                if redirect_uri_is_present:
                    self.create_new_issue('polluted_redirect_uri_allowed_with_redirection', message_info.getHttpService(),message_info.getUrl(),[message_info,modified_message_info], details)
                else:
                    self.create_new_issue('injected_redirect_uri_allowed_with_redirection', message_info.getHttpService(),message_info.getUrl(),[message_info,modified_message_info], details)
        except:
            print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])
    
    
    def tamper_redirect_uri_with_localhost_in_collab_domain(self,message_info, parameter):
        try:
            param_value= parameter.getValue()
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==decoded_url else False

            payload=self._collaborator.generatePayload(False)
            new_param_value= 'https://localhost.'+payload
            if is_url_encoded:
                new_param_value= self._helpers.urlEncode(new_param_value)

            modified_message_info= self.send_request_and_fire_alert(message_info, parameter, new_param_value, "tampered_redirect_uri_localhost")

            # Wait a prudent time to see if any request was issued to the collab payload
            time.sleep(60)
            collab_interactions= self._collaborator.fetchCollaboratorInteractionsFor(payload)
            if collab_interactions:
                details= get_collabs_interactions_summary(collab_interactions)
                self.create_new_issue('tampered_redirect_uri_localhost_with_redirection', message_info.getHttpService(),message_info.getUrl(),[message_info,modified_message_info], details)
        except:
            print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])


    def tamper_redirect_uri_with_parsing_discrepancies(self,message_info, parameter):
        
    
    
    def state_parameter_checks(self, message_info):
            analyzed_request= self._helpers.analyzeRequest(message_info.getRequest())
            analyzed_parameters = analyzed_request.getParameters()

            for parameter in analyzed_parameters:
                if 'state' in parameter.getName().lower():
                    start_new_thread(self.state_parameter_checks, (message_info, parameter,))
                    start_new_thread(self.replay_state_parameter, (message_info, parameter,))
                    start_new_thread(self.assess_state_parameter_entropy, (message_info, parameter,))
                    break
            return

    
    def assess_state_parameter_entropy(self, message_info, parameter):
        # TODO
        return
    
    
    def tamper_state_parameter(self, message_info, parameter):
        try:
            param_value= parameter.getValue()
            new_param_value= changeChar(param_value, random.randrange(1,len(param_value)))
            self.send_request_and_fire_alert(message_info, parameter, new_param_value, "tampered_state_parameter_allowed")
        except:
            print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])
        

    def replay_state_parameter(self, message_info, parameter):
        try:
            self.send_request_and_fire_alert(message_info, parameter, parameter.getValue(), "replayed_state_parameter_allowed")
        except:
            print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])


    def send_request_and_fire_alert(self, message_info, parameter, new_param_value, issue_id):
        if new_param_value is None:
            new_request= self._helpers.addParameter(message_info.getRequest(), parameter)
        else:
            new_request= self._helpers.updateParameter(message_info.getRequest(), self._helpers.buildParameter(
                parameter.getName(),
                new_param_value,
                parameter.getType()
            ))
        modified_message_info= self._callbacks.makeHttpRequest(message_info.getHttpService(), new_request)
        
        details=self.get_variations_summary(message_info, modified_message_info)
        if self.equal_status_code(message_info, modified_message_info):
            self.create_new_issue(issue_id, message_info.getHttpService(),message_info.getUrl(),[message_info,modified_message_info], details)
            return modified_message_info
        

    def get_variations_summary(self, first_message_info, second_message_info):
        response_variations= self._helpers.analyzeResponseVariations([first_message_info.getResponse(), second_message_info.getResponse()])
        variant_attributes= response_variations.getVariantAttributes()
        details=''
        for variant in variant_attributes:
            details=details+"Variation: "+variant
            details=details+" Original response: "+str(response_variations.getAttributeValue(variant, 0))
            details=details+" Modified response: "+str(response_variations.getAttributeValue(variant, 1))+"\n"
        return details
    
    def equal_status_code(self, first_message_info, second_message_info):
        first_response_status_code= self._helpers.analyzeResponse(first_message_info.getResponse()).getStatusCode()
        second_response_status_code= self._helpers.analyzeResponse(second_message_info.getResponse()).getStatusCode()
        return first_response_status_code==second_response_status_code


def contains_parameters(analyzed_parameters_list, lookup_param_list):
    for parameter in analyzed_parameters_list:
        for matching_param in lookup_param_list:
            if matching_param in parameter.getName().lower():
                return matching_param


def changeChar(buf, pos):
    chars= string.ascii_uppercase + string.digits + string.ascii_lowercase
    val= random.choice(chars)
    print("Replacing char offset=%d, old value=%r, new=%r"%(pos-1, buf[pos-1], val))
    print("Old buf: "+buf)
    buf = buf[:pos-1] + str(val)  + buf[pos:]
    print("New buf: "+buf)
    return buf

def get_collabs_interactions_summary(collab_interactions):
    details=''
    for interaction in collab_interactions:
        details= details + 'Collaborator Interaction\n'
        for int_name, int_value in interaction.getProperties().items():
            if int_name in ['request', 'response', 'raw_query']:
                details= details + int_name + " in Base64: " + int_value + "\n"
            else:
                details= details + int_name + ": " + int_value + "\n"
    return details

# def repeatByte(buf, pos, cant):
#     print("Repeating byte offset=%d, value=%r, cant=%i"%(pos-1, buf[pos-1], cant))
#     buf = buf[:pos-1] + buf[pos-1]*cant + buf[pos:]
#     return buf

# def insertRandomData(buf, pos, cant): 

#     randomString = ""
#     for _ in itertools.repeat(None, cant):
#         randomString+=chr(random.randrange(0,256))
#     print("Inserted after byte offset=0x%d random data %s"%(pos-1, randomString))

#     buf = buf[:pos-1] + buf[pos-1] + bytes(randomString, encoding='utf-8') + buf[pos:]

#     return buf

class CustomScanIssue(IScanIssue):
    def __init__(self, issue_id, httpService, url, httpMessages, detail=None):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        
        global issues_documentation
        issue_documentation=issues_documentation[issue_id]
        self._name = issue_documentation["name"]
        self._issue_background = issue_documentation["issue_background"]
        self._severity = issue_documentation["severity"]
        self._confidence= issue_documentation["confidence"]
        self._remediation_detail= issue_documentation["remediation_detail"]
        self._detail=detail

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
        return self._issue_background

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        if self._detail:
            return self._detail
        else:
            pass

    def getRemediationDetail(self):
        return self._remediation_detail

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
        
