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

from thread import start_new_thread

import sys
import json
import random
import string
from urlparse import urlparse
import time
import urllib


f = open('issues_documentation.json')
issues_documentation = json.load(f)


oauth_urls_identified=dict()
latest_oauth_server=dict()

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener, IExtensionStateListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        self._callbacks.setExtensionName("OAuth2.0 Extender")
        
        self._is_community_edition= False
        if 'community' in str(self._callbacks.getBurpVersion()).lower():
            print("Using Burp Community Edition. Will not use Burp Collaborator payloads")
            self._is_community_edition= True
        
        # obtain our output and error streams
        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # register ourselves as an HTTP listener
        self._callbacks.registerHttpListener(self)
        
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

        # User can just send one message. If required we could allow more than one
        if self._context.getInvocationContext() in invocation_allowed and len(self._context.selectedMessages) == 1:
            parentMenu = JMenuItem('Send to OAuth2.0 Extender', actionPerformed=self.MenuAction)
            menuList.add(parentMenu)

        return menuList

    def MenuAction(self, event):
        
        messageInfo = self._context.getSelectedMessages()[0]
        self.detect_oauth(messageInfo)


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        #if you want the request before leaving Burp or if you want to capture the request after it gets a response. For that, you have the Boolean messageIsRequest—a setting of true will capture the request before leaving, and false will capture it with a response.
        #Check if Message is a Request and then check if it is coming from tool "Proxy".  If so, then analyze the request and go through thev parameters and see if any match known OAuth parameters. If so, Report.
        if not messageIsRequest:
            if str(self._callbacks.getToolName(toolFlag)) == "Proxy":
                #print("Proxy is receiving a Request")
                analyzedRequest = self._helpers.analyzeRequest(messageInfo.getRequest())
                try:
                    self.detect_oauth(messageInfo)
                except:
                    print("Unexpected error: ", sys.exc_info()[0], sys.exc_info()[1])
            # else:
            #     print("WARNING: got message from unidentified tool: " + str(self._callbacks.getToolName(toolFlag)))
            #     print(self._helpers.bytesToString(messageInfo.getRequest()).encode('utf-8'))
              
    def detect_oauth(self, message_info):
        analyzed_request= self._helpers.analyzeRequest(message_info.getRequest())
        global latest_oauth_server
        # https://datatracker.ietf.org/doc/html/rfc6749#section-11.2.2
        oauth_parameters = { "client_id": False,
                            "response_type" : False,
                            "redirect_uri": False,
                            "scope": False, 
                            "state": False,
                            "nonce": False,
                            "code_challenge": False,
                            "code_challenge_method": False
                            }
        
        if analyzed_request.getParameters():
            analyzed_parameters = analyzed_request.getParameters()
            for parameter in analyzed_parameters:
                for oauth_parameter in oauth_parameters:
                    if parameter.getName().lower()  == oauth_parameter:
                        oauth_parameters[oauth_parameter] = parameter.getValue().lower()
                        
            # Count how many OAuth params we have
            param_count=0
            for oauth_param in oauth_parameters:
                if oauth_parameters[oauth_param]:
                    param_count+=1
            
            if oauth_parameters["client_id"]:
                if oauth_parameters["response_type"]:
                    message_info.setHighlight("blue")
                    message_info.setComment("OAuth 2.0 Authorization Request")
                    print("------  OAuth Identified   ------")
                    print("URL observed was : " + str(message_info.getUrl()))
                    print(" Parameters observed in the request indicating OAuth presence were:")
                    for item, value in oauth_parameters.items():
                        if value:
                            print(item+": "+value)
                    print("-- Authorization Type Detected: " + oauth_parameters['response_type'] + " --")               
                    self.start_security_checks(message_info, analyzed_parameters, oauth_parameters )
                    
                # No response_type. Check if we have an acceptable amount of parameters 
                elif param_count>=3:
                    message_info.setHighlight("blue")
                    message_info.setComment("OAuth 2.0 Authorization Request")
                    print("------  OAuth Identified   ------")
                    print("URL observed was : " + str(message_info.getUrl()))
                    print(" Parameters observed in the request indicating OAuth presence were:")
                    for item, value in oauth_parameters.items():
                       if value:
                            print(item+": "+value)
                    print("-- No Authorization Type Detected: defaulting to code --")
                    # Since there's no response_type we assume it's code (response_type is mandatory)
                    oauth_parameters["response_type"]="code"
                    self.start_security_checks(message_info, analyzed_parameters, oauth_parameters)
        
            else:
                self.start_security_checks(message_info, analyzed_parameters, oauth_parameters)

    def start_security_checks(self, message_info, analyzed_parameters, oauth_parameters):
        global latest_oauth_server
        message_service = message_info.getHttpService()
        response_type= oauth_parameters["response_type"]

        #Start Check if Implicit Mode by "Token" in response_type or Authorizaiton Code Mode by "code" in response_type
        if response_type and ("token" in response_type or "code" in response_type):
            print("Starting security checks: auth request")

            # Store some information that will be used to analyze the callback (redirect) request
            latest_oauth_server=dict()
            latest_oauth_server['server_url']= str(message_service)
            latest_oauth_server['response_type']= oauth_parameters["response_type"]
            
            
            # Perform checks according to response_type - Implicit (token) or Code modes
            if "token" in response_type:
                self.create_new_issue("using_implicit_mode",message_service,message_info.getUrl(),[message_info])

            else: 
                # TODO are we gonna leave this check? This is not an issue
                self.create_new_issue("using_code_mode",message_service,message_info.getUrl(),[message_info])
                
                
                if oauth_parameters["code_challenge"] or oauth_parameters["code_challenge_method"] == False:
                    self.create_new_issue("code_mode_without_PKCE",message_service,message_info.getUrl(),[message_info])
                    using_pkce_code_mode=False
                else:
                    using_pkce_code_mode=True

                self.response_type_checks(message_info, is_callback=False)
                

            # Checks applicable to both Code and Implicit modes
            if not oauth_parameters["state"]:
                if "code" in response_type and using_pkce_code_mode:
                    self.create_new_issue("no_state_parameter_code_flow_with_PKCE",message_service,message_info.getUrl(),[message_info])
                else:
                    self.create_new_issue("no_state_parameter",message_service,message_info.getUrl(),[message_info])

            if oauth_parameters["redirect_uri"]:
                latest_oauth_server['redirect_uri']= str(self._helpers.urlDecode(oauth_parameters['redirect_uri']))
                self.redirect_uri_checks(message_info)
            else:
                start_new_thread(self.inject_redirect_uri, (message_info,False,))
            
            print("Finishing security checks: auth request")
                
        elif response_type: 
            print("'response_type' " + response_type + "not recognized. Please FILE AN ISSUE in out Github with as much detail as possible!")
        
        elif not response_type and len(latest_oauth_server)>0:  
            analyze_callback_request= False
            redirect_uri_present= False

            if 'redirect_uri' in latest_oauth_server and self.urls_match(latest_oauth_server['redirect_uri'], message_info):                
                analyze_callback_request= True
                redirect_uri_present= True

            elif 'redirect_uri' not in latest_oauth_server: 
                #No redirect_uri, will use tighter comparisons then
                for parameter in analyzed_parameters:
                    if latest_oauth_server['response_type'] == parameter.getName().lower():
                        analyze_callback_request= True
            
            if analyze_callback_request:            
                print("Starting security checks: callback request")
                message_info.setHighlight("blue")
                message_info.setComment("OAuth 2.0 Callback Request")

                self.state_parameter_checks(message_info)
                self.response_type_checks(message_info, is_callback=True)

                if redirect_uri_present:
                    # It is safe to reset this variable
                    latest_oauth_server=dict()
                    print("Finishing security checks: : callback request")
            
        
        return
    
    def urls_match(self, url, message_info):
        parsed_request_url= urlparse(str(message_info.getUrl()))
        parsed_url=urlparse(url)
        
        parsed_request_url= parsed_request_url._replace(netloc= parsed_request_url.netloc.split(':')[0] )
        parsed_url= parsed_url._replace(netloc= parsed_url.netloc.split(':')[0] )
        
        same_host=parsed_request_url.netloc==parsed_url.netloc
        same_path=parsed_request_url.path==parsed_url.path
        same_scheme=parsed_request_url.scheme==parsed_url.scheme
        return same_host and same_path and same_scheme

    
    def create_new_issue(self, issue_id, message_service, url, message_info_list, details=None):
        issue=CustomScanIssue(   
                            issue_id,
                            message_service, 
                            url,
                            message_info_list, 
                            details
                            )
        print("New issue: "+issue.getIssueName()+" ("+issue_id+") ")
        if not self._is_community_edition:
            self._callbacks.addScanIssue(issue)

    
    def response_type_checks(self, message_info, is_callback):
        analyzed_request= self._helpers.analyzeRequest(message_info.getRequest())
        analyzed_parameters = analyzed_request.getParameters()
        global latest_oauth_server

        for parameter in analyzed_parameters:
            param_name= parameter.getName().lower()
            param_value= parameter.getValue().lower()

            if not is_callback and 'response_type' in param_name and 'token' in param_value:
                print("Tampering with response_type=code for response_type=token")
                start_new_thread(self.tamper_with_code_response_type, (message_info, parameter))
            elif is_callback and 'code' in param_name or 'token' in param_name:
                print("response_type checks in callback")
                start_new_thread(self.check_secrets_in_url, (message_info, parameter, latest_oauth_server))
                start_new_thread(self.replay_auth_code, (message_info, parameter, latest_oauth_server))                 
    
    def replay_auth_code(self, message_info, parameter, latest_oauth_server):
        try:    
            param_name= parameter.getName().lower()
            replay_code=False
            if 'redirect_uri' in latest_oauth_server:
                if 'code' in latest_oauth_server['response_type'] and "code" in param_name:
                    replay_code=True
            # TODO Since we do not have the redirect_uri these checks are less certain. Will do sth about it?
            else:
                if latest_oauth_server['response_type']==param_name and 'code' in param_name:
                    replay_code=True

            if replay_code:
                self.send_request_and_fire_alert(message_info, parameter, parameter.getValue(), "auth_code_replayed")
        except:
            print("Unexpected error replay_auth_code: ", sys.exc_info()[0], sys.exc_info()[1])

    def check_secrets_in_url(self, message_info, parameter, latest_oauth_server):
        try:
            message_service= message_info.getHttpService()
            url=message_info.getUrl()
            param_name=parameter.getName().lower()

            if parameter.getType()==IParameter.PARAM_URL:
                if 'redirect_uri' in latest_oauth_server:
                    if 'token' in latest_oauth_server['response_type'] and "token" in param_name: 
                        self.create_new_issue("access_token_as_URL_parameter", message_service, url, [message_info])
                    elif 'code' in latest_oauth_server['response_type'] and "code" in param_name:
                        self.create_new_issue("authorization_code_as_URL_parameter", message_service, url, [message_info])
                
                # TODO Since we do not have the redirect_uri these checks are less certain. Will do sth about it?
                elif latest_oauth_server['response_type']==param_name:
                    if 'token' in param_name:
                        self.create_new_issue("access_token_as_URL_parameter", message_service, url, [message_info])
                    elif 'code' in param_name:    
                        self.create_new_issue("authorization_code_as_URL_parameter",message_service, url, [message_info])
        except:
            print("Unexpected error check_secrets_in_url: ", sys.exc_info()[0], sys.exc_info()[1])

    
    def tamper_with_code_response_type(self,message_info, parameter):
        try:    
            if 'response_type' in parameter.getName().lower():
                self.send_request_and_fire_alert(message_info, parameter, 'id_token', "oauth_server_allows_implicit_auth_id_token")
                self.send_request_and_fire_alert(message_info, parameter, 'token', "oauth_server_allows_implicit_auth_token")
        except:
            print("Unexpected error tamper_with_code_response_type: ", sys.exc_info()[0], sys.exc_info()[1])
    
    def redirect_uri_checks(self, message_info):
        analyzed_request= self._helpers.analyzeRequest(message_info.getRequest())
        analyzed_parameters = analyzed_request.getParameters()

        for parameter in analyzed_parameters:
            if 'redirect' in parameter.getName().lower():
                print("Tampering redirect_uri parameter..")
                start_new_thread(self.tamper_redirect_uri_with_subdomain, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_path_traversal, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_collab_domain, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_parameter_pollution, (message_info, parameter))
                start_new_thread(self.domain_allowed_in_redirect_uri, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_localhost_in_collab_domain, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_parsing_discrepancies, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_as_path, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_with_redirect_to, (message_info, parameter,))
                start_new_thread(self.tamper_redirect_uri_plaintext, (message_info, parameter,))
                break
        return


    def tamper_redirect_uri_with_subdomain(self,message_info, parameter):
        try:    
            param_value= parameter.getValue()
            
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==len(decoded_url) else True

            parsed_url= urlparse(decoded_url)

            if 'www.' in parsed_url.netloc:
                parsed_url= parsed_url._replace(netloc='www.test-subdomain.'+parsed_url.netloc.replace('www.','',1))
            else:
                parsed_url= parsed_url._replace(netloc='test-subdomain.'+parsed_url.netloc)
            
            new_param_value=parsed_url.geturl()
            if is_url_encoded:
                new_param_value= urllib.quote(new_param_value, safe='')

            self.send_request_and_fire_alert(message_info, parameter, new_param_value, "subdomain_allowed_in_redirect_uri")
        except:
            print("Unexpected error tamper_redirect_uri_with_subdomain: ", sys.exc_info()[0], sys.exc_info()[1])


    def tamper_redirect_uri_with_path_traversal(self,message_info, parameter):
        try:    
            param_value= parameter.getValue()
            
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==len(decoded_url) else True

            parsed_url= urlparse(decoded_url)
            
            if parsed_url.path.endswith("/"):
                parsed_url= parsed_url._replace(path= parsed_url.path + '../')
            else:
                parsed_url= parsed_url._replace(path= parsed_url.path + '/../')
            
            new_param_value=parsed_url.geturl()
            if is_url_encoded:
                new_param_value= urllib.quote(new_param_value, safe='')
                

            self.send_request_and_fire_alert(message_info, parameter, new_param_value, "directory_traversal_in_redirect_uri")
        except:
            print("Unexpected error tamper_redirect_uri_with_path_traversal: ", sys.exc_info()[0], sys.exc_info()[1])

    
    def tamper_redirect_uri_with_parameter_pollution(self, message_info, parameter):
        try:
            param_value= parameter.getValue()
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==len(decoded_url) else True

            payload= self.get_collaborator_payload()
            
            parsed_url= urlparse(decoded_url)
            parsed_url= parsed_url._replace(netloc=payload)

            new_param_value=parsed_url.geturl()
            if is_url_encoded:
                new_param_value= urllib.quote(new_param_value, safe='')

            # Will try adding the new redirect uri before and after the legitimate one
            # After legitimate redirect uri
            new_param= self._helpers.buildParameter('redirect_uri', new_param_value, parameter.getType())
            modified_message_info= self.send_request_and_fire_alert(message_info, new_param, None, "polluted_redirect_uri_allowed")
            self.fetch_collab_interactions_and_fire_alert(message_info, modified_message_info, [payload], 'polluted_redirect_uri_allowed_with_redirection')

            # Remove the legitimate URI and put it back at the end
            modified_message_info= self.send_request_and_fire_alert(message_info, new_param, None, "polluted_redirect_uri_allowed", parameter)
            self.fetch_collab_interactions_and_fire_alert(message_info, modified_message_info, [payload], 'polluted_redirect_uri_allowed_with_redirection')
            
        except:
            print("Unexpected error tamper_redirect_uri_with_parameter_pollution: ", sys.exc_info()[0], sys.exc_info()[1])
    
    
    def tamper_redirect_uri_with_collab_domain(self, message_info, parameter):
        try:
            param_value= parameter.getValue()
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==len(decoded_url) else True

            payload= self.get_collaborator_payload()
            
            parsed_url= urlparse(decoded_url)
            parsed_url= parsed_url._replace(netloc=payload)

            new_param_value=parsed_url.geturl()
            if is_url_encoded:
                new_param_value= urllib.quote(new_param_value, safe='')

            modified_message_info= self.send_request_and_fire_alert(message_info, parameter, new_param_value, "tampered_redirect_uri")
            self.fetch_collab_interactions_and_fire_alert(message_info, modified_message_info, [payload], 'tampered_redirect_uri_with_redirection')
        except:
            print("Unexpected error tamper_redirect_uri_with_collab_domain: ", sys.exc_info()[0], sys.exc_info()[1])


    def domain_allowed_in_redirect_uri(self, message_info, parameter):
        try:    
            param_value= parameter.getValue()
            
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==len(decoded_url) else True

            parsed_url= urlparse(decoded_url)
            parsed_url= parsed_url._replace(path= '')
            
            new_param_value=parsed_url.geturl()
            if is_url_encoded:
                new_param_value= urllib.quote(new_param_value, safe='')

            self.send_request_and_fire_alert(message_info, parameter, new_param_value, "domain_allowed_in_redirect_uri")
        except:
            print("Unexpected error domain_allowed_in_redirect_uri: ", sys.exc_info()[0], sys.exc_info()[1])


    def inject_redirect_uri(self, message_info):
        try:
            payload= self.get_collaborator_payload()
            new_param_value= 'https://'+payload
            new_param_value= urllib.quote(new_param_value, safe='')          
            new_param= self._helpers.buildParameter('redirect_uri', new_param_value, IParameter.PARAM_URL)

            modified_message_info= self.send_request_and_fire_alert(message_info, new_param, None, "injected_redirect_uri_allowed")
            self.fetch_collab_interactions_and_fire_alert(message_info, modified_message_info, [payload], 'injected_redirect_uri_allowed_with_redirection')
        except:
            print("Unexpected error inject_redirect_uri: ", sys.exc_info()[0], sys.exc_info()[1])
    
    
    def tamper_redirect_uri_with_localhost_in_collab_domain(self,message_info, parameter):
        try:
            param_value= parameter.getValue()
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==len(decoded_url) else True

            payload= self.get_collaborator_payload()

            parsed_url= urlparse(decoded_url)
            parsed_url= parsed_url._replace(netloc='localhost.'+payload)
            
            new_param_value= parsed_url.geturl()
            if is_url_encoded:
                new_param_value= urllib.quote(new_param_value, safe='')

            modified_message_info= self.send_request_and_fire_alert(message_info, parameter, new_param_value, "tampered_redirect_uri_localhost")
            self.fetch_collab_interactions_and_fire_alert(message_info, modified_message_info, [payload], 'tampered_redirect_uri_localhost_with_redirection')
        except:
            print("Unexpected error tamper_redirect_uri_with_localhost_in_collab_domain: ", sys.exc_info()[0], sys.exc_info()[1])


    def tamper_redirect_uri_with_parsing_discrepancies(self,message_info, parameter):
        # https://default-host.com&@foo.evil-user.net#@bar.evil-user.net/
        try:
            param_value= parameter.getValue()
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==len(decoded_url) else True

            payloads= [self.get_collaborator_payload(), self.get_collaborator_payload()]
            parsed_url= urlparse(decoded_url)
            parsed_url= parsed_url._replace(netloc=parsed_url.netloc+'&@'+payloads[0]+'#@'+payloads[1])
            new_param_value=parsed_url.geturl()
            if is_url_encoded:
                new_param_value= urllib.quote(new_param_value, safe='')

            modified_message_info= self.send_request_and_fire_alert(message_info, parameter, new_param_value, "tamper_redirect_uri_parsing_discrepancies")
            self.fetch_collab_interactions_and_fire_alert(message_info, modified_message_info, payloads, 'tamper_redirect_uri_parsing_discrepancies_with_redirection')
                
        except:
            print("Unexpected error tamper_redirect_uri_with_parsing_discrepancies: ", sys.exc_info()[0], sys.exc_info()[1])

    def tamper_redirect_uri_with_as_path(self,message_info, parameter):
        # This check is suppossed to work with code flow only. We use it for both options
        try:
            param_value= parameter.getValue()
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==len(decoded_url) else True

            parsed_url= urlparse(decoded_url)
            payload= self.get_collaborator_payload()
            
            new_param_value= 'https://'+payload+'/'+parsed_url.netloc+parsed_url.path
            if is_url_encoded:
                new_param_value= urllib.quote(new_param_value, safe='')

            modified_message_info= self.send_request_and_fire_alert(message_info, parameter, new_param_value, "tamper_redirect_uri_as_collab_path")
            self.fetch_collab_interactions_and_fire_alert(message_info, modified_message_info, [payload], 'tamper_redirect_uri_as_collab_path_with_redirection')
        except:
            print("Unexpected error tamper_redirect_uri_with_as_path: ", sys.exc_info()[0], sys.exc_info()[1])
    
    def tamper_redirect_uri_with_redirect_to(self, message_info, parameter):
        # This check is suppossed to work with implicit flow only. We use it for both options
        try:
            param_value= parameter.getValue()
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==len(decoded_url) else True

            payload= self.get_collaborator_payload()

            if is_url_encoded:
                new_param_value= urllib.quote(decoded_url+ urllib.quote('&redirect_to=https://'+payload+'/' , safe=''), safe='')
            else:
                new_param_value= urllib.quote(decoded_url+ '&redirect_to=https://'+payload+'/', safe='')

            modified_message_info= self.send_request_and_fire_alert(message_info, parameter, new_param_value, "tamper_redirect_uri_with_redirect_to")
            self.fetch_collab_interactions_and_fire_alert(message_info, modified_message_info, [payload], 'tamper_redirect_uri_with_redirect_to_with_redirection')
        except:
            print("Unexpected error tamper_redirect_uri_with_redirect_to: ", sys.exc_info()[0], sys.exc_info()[1])

    def tamper_redirect_uri_plaintext(self, message_info, parameter):
        # This check is suppossed to work with implicit flow only. We use it for both options
        try:
            param_value= parameter.getValue()
            
            decoded_url= self._helpers.urlDecode(param_value)
            is_url_encoded= False if len(param_value)==len(decoded_url) else True

            parsed_url= urlparse(decoded_url)

            if parsed_url.scheme=='https':
                parsed_url= parsed_url._replace(scheme='http')

            new_param_value=parsed_url.geturl()
            if is_url_encoded:
                new_param_value= urllib.quote(new_param_value, safe='')

            self.send_request_and_fire_alert(message_info, parameter, new_param_value, "tamper_redirect_uri_plaintext")
        except:
            print("Unexpected error tamper_redirect_uri_plaintext: ", sys.exc_info()[0], sys.exc_info()[1])
    
    def get_collaborator_payload(self):
        if self._is_community_edition:
            return 'google.com'
        else:
            return self._collaborator.generatePayload(True)
    
    def fetch_collab_interactions_and_fire_alert(self, message_info, modified_message_info, payload_list, issue_id):
        if self._is_community_edition:
            return
        # Wait a prudent time to see if any request was issued to the collab payload
        # TODO check the referrer header and URL parameters to make sure code/state are contained in it. If they are not, it's just open redifect
        time.sleep(60)
        for payload in payload_list:
            collab_interactions= self._collaborator.fetchCollaboratorInteractionsFor(payload)
            if collab_interactions:
                details= get_collabs_interactions_summary(collab_interactions)
                self.create_new_issue(issue_id, message_info.getHttpService(),message_info.getUrl(),[message_info,modified_message_info], details)
    
    def state_parameter_checks(self, message_info):
            analyzed_request= self._helpers.analyzeRequest(message_info.getRequest())
            analyzed_parameters = analyzed_request.getParameters()

            for parameter in analyzed_parameters:
                if 'state' in parameter.getName().lower():
                    print("Tampering state parameter..")
                    start_new_thread(self.replay_state_parameter, (message_info, parameter,))
                    start_new_thread(self.tamper_state_parameter, (message_info, parameter,))
                    start_new_thread(self.assess_state_parameter_entropy, (message_info, parameter,))
                    break
            return

    
    def assess_state_parameter_entropy(self, message_info, parameter):
        # TODO we'll need a library to measure entropy
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


    def send_request_and_fire_alert(self, message_info, parameter, new_param_value, issue_id, param_to_delete=None):            
        
        if new_param_value:
            new_request= self._helpers.updateParameter(message_info.getRequest(), self._helpers.buildParameter(
                parameter.getName(),
                new_param_value,
                parameter.getType()
            ))
        else:
            new_request= self._helpers.addParameter(message_info.getRequest(), parameter)

            if param_to_delete:
                # Remove the legitimate URI and put it back at the end
                new_request= self._helpers.removeParameter(new_request, param_to_delete)
                new_request= self._helpers.addParameter(new_request, param_to_delete)
            
        modified_message_info= self._callbacks.makeHttpRequest(message_info.getHttpService(), new_request)
        
        details=self.get_variations_summary(message_info, modified_message_info)
        if self.equal_status_code(message_info, modified_message_info):
            self.create_new_issue(issue_id, message_info.getHttpService(),message_info.getUrl(),[message_info,modified_message_info], details)
            return modified_message_info
        

    def get_variations_summary(self, first_message_info, second_message_info):
        # TODO printing this stuff might not be neccessary because Burp already allows the user to compare reponses
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
            if int_name in ['protocol', 'type', 'query_type', 'client_ip', 'time_stamp']:
                details= details + int_name + ": " + int_value + '\n'                
    return details


def get_inherited_doc(issue_documentation):
    global issues_documentation
    if 'inherit_from' in issue_documentation:
        # Get inherited documentation recursively
        inherit_issue_documentation= get_inherited_doc(issues_documentation[issue_documentation['inherit_from']])
        
        # Override the rest of the existing fields
        if "name" in issue_documentation:
            inherit_issue_documentation["name"]= issue_documentation["name"]
        if "issue_background" in issue_documentation:
            inherit_issue_documentation["issue_background"]= issue_documentation["issue_background"]
        if "severity" in issue_documentation:
            inherit_issue_documentation["severity"]= issue_documentation["severity"]
        if "confidence" in issue_documentation:
            inherit_issue_documentation["confidence"]= issue_documentation["confidence"]
        if "remediation_detail" in issue_documentation:
            inherit_issue_documentation["remediation_detail"]= issue_documentation["remediation_detail"]
        
        return inherit_issue_documentation
    else:
        return issue_documentation

class CustomScanIssue(IScanIssue):
    def __init__(self, issue_id, httpService, url, httpMessages, detail=None):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        
        global issues_documentation
        issue_documentation= get_inherited_doc(issues_documentation[issue_id]) 
        self._name = issue_documentation["name"]

        self._detail=detail
        self._remediation_detail = issue_documentation["remediation_detail"]
        self._confidence= issue_documentation["confidence"]
        self._severity = issue_documentation["severity"]
        self._issue_background = issue_documentation["issue_background"]

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
        
