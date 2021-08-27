import json
from ..classes import Output
from requests import Response

class HeaderAuditor:

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

    def analyseHeaders(self, response : Response ):
        results = Output.HeaderResult()

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

    def getHeadersReportData(self, results : Output.HeaderResult):
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

class CookieAuditor:
    #HTTPOnly
    #Secure - When a secure flag is used, then the cookie will only be sent over HTTPS
    #SameSite - An HttpOnly Cookie is a tag added to a browser cookie that prevents client-side scripts from accessing data
    #Cookie lifetime - Instead of expiring when the client is closed, permanent cookies expire at a specific date (Expires) or after a specific length of time (Max-Age). 
    #Path - Only valid on specifics paths
    #Domain - With domain set, cookies will be sent to that domain and all its subdomains. Not always ideal for different sites with independent authentication
    #Host-only 

    #Beware that cookie auditing via this tool is somewhat useless on sites where users have to consent to cookies via the website GUI
    #For more on cookie consent law see https://ico.org.uk/for-organisations/guide-to-pecr/cookies-and-similar-technologies/
    def analyseCookies(self, response : Response):
        cookiesResults = self.getCookieData(response)
        
    def cookieRecommendations(self, cookieResults : Output.CookieResults):
        cookieResults.recommendations = {}
        for r in cookieResults.cookies:
            if r.httpOnly == False:
                if not "HTTPOnly" in cookieResults.recommendations:
                    cookieResults.recommendations["HTTPOnly"] = "Some recommendation"
            if r.secure == False:
                if not "Secure" in cookieResults.recommendations:
                    cookieResults.recommendations["HTTPOnly"] = "Some recommendation"
            if not r.sameSite:
                #Additional recommendation about strict vs lax
                if not "Samesite" in cookieResults.recommendations:
                    cookieResults.recommendations["Samesite"] = "Some recommendation"
            #if r.lifetime:
                #some recommendation about properly invalidating cookies if lifetime is too high

            # if r.path:
                #some recommendatin about cookie scope creep
            # if r.domain:
                #some recommendatin about cookie scope creep in terms of subdomains
        
    def getCookieData(self, response : Response):
        cookiesResults = Output.CookieResults()
        for cookie in response.cookies:
           # attrs = cookie.__a
            cookieResult = Output.CookieResult()
            if cookie.has_nonstandard_attr('HttpOnly'):
                cookieResult.httpOnly = True
            if cookie.secure:
                cookieResult.secure = True
            if cookie.has_nonstandard_attr('SameSite'):
                cookieResult.sameSite = cookie.get_nonstandard_attr('SameSite')

            cookieResult.lifetime = cookie.expires
            cookieResult.path = cookie.path
            cookieResult.domain = cookie.domain

            cookiesResults.cookies.append(cookieResult)

            return cookiesResults