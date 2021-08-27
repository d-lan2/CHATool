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
        cookiesResults = self.cookieRecommendations(cookiesResults)
        return cookiesResults
        
    def cookieRecommendations(self, cookieResults : Output.CookieResults):
        cookieResults.recommendations = {}
        for r in cookieResults.cookies:
            if r.httpOnly == False:
                if not "HTTPOnly" in cookieResults.recommendations:
                    cookieResults.recommendations["HTTPOnly"] = "Using the HttpOnly flag when generating a cookie helps mitigate the risk of client side script accessing the protected cookie. His assists in preventing attacks such as session hijacking and cookie theft."
            if r.secure == False:
                if not "Secure" in cookieResults.recommendations:
                    cookieResults.recommendations["Secure"] = "When a secure flag is used, then the cookie will only be sent over HTTPS. This reduces the chance of cookie theft via sniffing and man-in-the-middle attack"
            if not r.sameSite or r.sameSite == "None":
                #Additional recommendation about strict vs lax
                if not "Samesite" in cookieResults.recommendations:
                    cookieResults.recommendations["Samesite"] = "SameSite prevents the browser from sending this cookie along with cross-site requests. The main goal is to mitigate the risk of cross-origin information leakage. It also provides some protection against cross-site request forgery attacks."
            #maxage or expirey date > 30mins
            #See OWASP recommendaitons here: https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Session_Management_Cheat_Sheet.md
            #the expired attribute of the cookie class coverts a date-time into seconds
            if (r.maxage is None and r.expires is None) or  (r.maxage and r.maxage > 1800) or (r.expires and r.expires > 1800):
                #some recommendation about properly invalidating cookies if lifetime is too high
                if not "Lifetime" in cookieResults.recommendations:
                    cookieResults.recommendations["Lifetime"] = "OWASP states 'common idle timeouts ranges are 2-5 minutes for high-value applications and 15-30 minutes for low risk applications'. Therefore, if a cookie stores or allows access to sensitive information considder setting the Max-Age an Expires cookie attributes to within 30 minutes of the time of creation."
            if r.path == '/':
                if not "Path" in cookieResults.recommendations:
                    cookieResults.recommendations["Path"] = "A cookie with an overly broad path can be accessed through other applications on the same domain, this unnecessarily increases the overall attack surface."
            if r.domain:
                if not "Domain" in cookieResults.recommendations:
                    cookieResults.recommendations["Domain"] = "With domain set, cookies will be sent to that domain and all its subdomains. Remove domain attribute to limit cookie to origin host only"

            return cookieResults
        
    def getCookieData(self, response : Response):
        cookiesResults = Output.CookieResults()
        for cookie in response.cookies:
            cookieResult = Output.CookieResult()
            if cookie.has_nonstandard_attr('HttpOnly'):
                cookieResult.httpOnly = True
            if cookie.secure:
                cookieResult.secure = True
            if cookie.has_nonstandard_attr('SameSite'):
                cookieResult.sameSite = cookie.get_nonstandard_attr('SameSite')
            if cookie.has_nonstandard_attr('Max-Age'):
                cookieResult.maxage = cookie.get_nonstandard_attr('Max-Age')

            cookieResult.expires = cookie.expires
            cookieResult.path = cookie.path
            cookieResult.domain = cookie.domain

            cookiesResults.cookies.append(cookieResult)

            return cookiesResults