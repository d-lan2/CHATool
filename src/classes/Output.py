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

class CookieResult:
    def __init__(self, secure = None, httpOnly = None, path = None, domain = None, lifetime = None, sameSite = None):
         self.secure = secure or False
         self.httpOnly = httpOnly or False
         self.path = path or ""
         self.domain = domain or ""
         self.lifetime = lifetime or ""
         self.sameSite = sameSite or False
         self.recommendations = {}