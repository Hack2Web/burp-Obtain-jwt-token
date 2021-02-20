# python imports
import re
import sys
 
# Burp specific imports
from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import ICookie
 
# For using the debugging tools from
# https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass
 
class Cookie(ICookie):
     
    def getDomain(self):
        return self.cookie_domain
 
    def getPath(self):
        return self.cookie_path
 
    def getExpiration(self):
        return self.cookie_expiration
 
    def getName(self):
        return self.cookie_name
 
    def getValue(self):
        return self.cookie_value
 
    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None, cookie_expiration=None):
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.cookie_path = cookie_path
        self.cookie_expiration = cookie_expiration
 
class BurpExtender(IBurpExtender, ISessionHandlingAction):
 
    #
    # Define config and gui variables
    #
 
    cookieName = 'token'
    cookieDomain = 'xxx.com'
 
    #
    # Define some cookie functions
    #
 
    def deleteCookie(self, domain, name):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            #self.stdout.println("%s = %s" % (cookie.getName(), cookie.getValue())) 
            if cookie.getDomain() == domain and cookie.getName() == name:
                cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None,  cookie.getPath(), cookie.getExpiration())
                self.callbacks.updateCookieJar(cookie_to_be_nuked)
                break
 
    def createCookie(self, domain, name, value, path=None, expiration=None):
        cookie_to_be_created = Cookie(domain, name, value,  path, expiration)
        self.callbacks.updateCookieJar(cookie_to_be_created)
 
    def setCookie(self, domain, name, value):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name:
                cookie_to_be_set = Cookie(cookie.getDomain(), cookie.getName(), value,  cookie.getPath(), cookie.getExpiration())
                self.callbacks.updateCookieJar(cookie_to_be_set)
                break
 
    def getCookieValue(self, domain, name):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name:
                return cookie.getValue()
 
 
    #
    # implement IBurpExtender
    #
 
    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self.callbacks = callbacks
 
        # obtain an extension helpers object
        self.helpers = callbacks.getHelpers()
 
        # set our extension name
        callbacks.setExtensionName("JWT - Store & Set")
 
        # register ourselves a Session Handling Action
        callbacks.registerSessionHandlingAction(self)
 
        # Used by the custom debugging tools
        sys.stdout = callbacks.getStdout()
 
        print("DEBUG: JWT - Store & Set - Enabled!")
 
        return
 
    #
    # Implement ISessionHandlingAction
    #
 
    def getActionName(self):
        return "JWT - Store & Set"
 
    def performAction(self, current_request, macro_items):
        if len(macro_items) >= 0:
            # grab some stuff from the current request
            req_text = self.helpers.bytesToString(current_request.getRequest())
 
            current_macro = macro_items[0]
            macro_resp = current_macro.getResponse()
            macro_resp_info = self.helpers.analyzeResponse(macro_resp)
 
            # parse the response & search for jwt
            if macro_resp:
                macro_resp_body = macro_resp[macro_resp_info.getBodyOffset():]
                macro_resp_text = self.helpers.bytesToString(macro_resp_body)
                search_re = '"%s":"(.*?)"' % self.cookieName
                search = re.search(search_re, macro_resp_text, re.IGNORECASE)
 
                # we have a jwt in the macro response
                if search:
                    jwt = search.group(1)
 
                    # set the cookie value in the cookie jar
                    self.createCookie(self.cookieDomain, self.cookieName, jwt)
 
                    # replace the old token with the stored value
                    header_replace = "%s: %s" % (self.cookieName, jwt)
                    req_text = re.sub(r"\r\n" + self.cookieName + ": .*\r\n", "\r\n" + header_replace + "\r\n" , req_text)
 
                    # set the current request
                    current_request.setRequest(self.helpers.stringToBytes(req_text))
 
try:
    FixBurpExceptions()
except:
    pass