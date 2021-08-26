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
        "Feature-Policy"
    ]
    
    deprecatedHeaders = [
        "Expect-CT",
        "Public-Key-Pins",
        "X-XSS-Protection"
    ]

    def analyseHeaders(self, response):
        results = Output.Result()
        for header in self.allSecurityHeaders():
            if header in response.headers:
                results.presentHeaders.append(header)
            else:
                if header in self.activeHeaders:
                    results.missingHeaders.append(header)

            if header in self.almostDeprecatedHeaders and header in response.headers:
                results.presentAlmostDeprecatedHeaders.append(header)

            if header in self.deprecatedHeaders and header in response.headers:
                results.presentDeprecatedHeaders.append(header)
                
        results.headersReportData = self.getHeadersReportData(results)

        return results

    def getHeadersReportData(self, results : Output.Result):
        data = self.getHeadersJson(self.headerJsonLocation)
        headersToAddToReport = results.missingHeaders + results.presentAlmostDeprecatedHeaders + results.presentDeprecatedHeaders
        results.headersReportData = {}
        for h in headersToAddToReport:
            if h in data:
                results.headersReportData[h] = data[h]
        
        return results.headersReportData

    def getHeadersJson(self, path):
        with open(path, encoding="utf8") as f:
            data = json.load(f)
        return data
