import requests
import json
from ..classes import Output

class Auditor:

    @classmethod
    def allSecurityHeaders(cls):
        list = cls.activeHeaders + cls.almostDeprecatedHeaders + cls.deprecatedHeaders
        return list

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

    def getMissingHeaderData(self, results):
        data = self.getHeadersJson('src\\assets\\HeaderData.json')
        results.missingHeaderData = {}
        for m in results.missingHeaders:
            if m in data:
                results.missingHeaderData[m] = data[m]
        return results.missingHeaderData
    
    def getHeadersJson(self, path):
        with open(path, encoding="utf8") as f:
            data = json.load(f)
        return data
