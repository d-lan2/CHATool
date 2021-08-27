from typing import List


class HeaderResult:
    def __init__(self):
        self.message = None
        self.errors = None
        self.missingHeaders = []
        self.presentHeaders = []
        self.presentDeprecatedHeaders = []
        self.presentAlmostDeprecatedHeaders = []
        self.headersReportData = {}
    
class CookieResults:
    def __init__(self):
         self.cookies = []
         self.recommendations = {}

class CookieResult:
    def __init__(self, secure = None, httpOnly = None, path = None, domain = None, expires = None, maxage = None, sameSite = None):
         self.secure = secure or False
         self.httpOnly = httpOnly or False
         self.path = path or None
         self.domain = domain or None
         self.expires = expires or None
         self.maxage = maxage or None
         self.sameSite = sameSite or False