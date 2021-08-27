"""CHATool Cookie and Header Auditor Tool"""

from .src.classes.HTTP import HTTP
from .src.services.Auditor import *
from .src.services.WordWriter import WordWriter


def main():
    print("Welcome to CHATool!")
    print("The Cookie Header Audior Tool")
    url = input("Input url to scan the security headers:")
    responseCode = parameterisedMain(url,"output\\test3.docx")
    print("Status code:" + str(responseCode))
    input("Press enter to exit")
    
def parameterisedMain(url,outputfilepath, cookieDict = None):
    response = HTTP.get(url, cookieDict)
    headerResults = HeaderAuditor().analyseHeaders(response)
    cokkieResults = CookieAuditor().analyseCookies(response)
    WordWriter().writeDoc(outputfilepath, headerResults, cokkieResults)

    return response.status_code


if __name__ == '__main__':
    main()