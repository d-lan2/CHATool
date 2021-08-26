import requests
import json
from ..classes import Output

class Auditor:

    @classmethod
    def allSecurityHeaders(cls):
        list = cls.activeHeaders + cls.almostDeprecatedHeaders + cls.deprecatedHeaders
        return list

    headerJsonLocation = 'src\\assets\\HeaderData.json'

    activeHeaders = [
        #see https://owasp.org/www-project-secure-headers/
        #Active headers
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
        "X-Permitted-Cross-Domain-Policies",
        "Referrer-Policy",
        "Clear-Site-Data",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy"  
    ]

    almostDeprecatedHeaders = [
        "Feature-Policy",
        "Expect-CT"
    ]
    
    deprecatedHeaders = [
        "Public-Key-Pins",
        "X-XSS-Protection"
    ]

    def analyseHeaders(self, response):
        results = Output.Result()
        for header in self.allSecurityHeaders():
            if header in response.headers:
                results.presentHeaders.append(header)
            else:
                results.missingHeaders.append(header)

            if header in self.almostDeprecatedHeaders and header in response.headers:
                results.presentAlmostDeprecatedHeaders.append(header)

            if header in self.deprecatedHeaders and header in response.headers:
                results.presentDepricatedHeaders.append(header)
                

        return results

    def getMissingHeadersReportData(self, results : Output.Result):
        data = self.getHeadersJson(self.headerJsonLocation)
        results.missingHeadersReportData = {}
        for h in results.missingHeaders:
            if h in data:
                results.missingHeadersReportData[h] = data[h]
        
        return results.missingHeadersReportData
    
    def getDeprecatedHeadersReportData(self, results : Output.Result):
        data = self.getHeadersJson(self.headerJsonLocation)
        results.deprecatedHeadersReportData = {}
        for h in results.presentDepricatedHeaders:
            if h in data:
                results.deprecatedHeadersReportData[h] = data[h]
        return results.deprecatedHeadersReportData

    def getAlmostDeprecatedHeadersReportData(self, results : Output.Result):
        data = self.getHeadersJson(self.headerJsonLocation)
        results.almostDeprecatedHeadersReportData = {}
        for h in results.presentAlmostDepricatedHeaders:
            if h in data:
                results.almostDeprecatedHeadersReportData[h] = data[h]
        return results.almostDeprecatedHeadersReportData

    def getHeadersJson(self, path):
        with open(path, encoding="utf8") as f:
            data = json.load(f)
        return data
