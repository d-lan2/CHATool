"""CHATool Cookie and Header Auditor Tool"""

from .src.classes.HTTP import HTTP
from .src.services.Auditor import HeaderAuditor
from .src.services.WordWriter import WordWriter


def main(self):
    print("Welcome to CHATool!")
    print("The Cookie Header Audior Tool")
    url = input("Input url to scan the security headers:")
    responseCode = self.parameterisedMain(url,"output\\test3.docx")
    print("Status code:" + str(responseCode))
    input("Press enter to exit")
    
def parameterisedMain(url,outputfilepath):
    response = HTTP.get(url)
    results = HeaderAuditor().analyseHeaders(response)
    WordWriter().writeDoc(results, outputfilepath)
    return response.status_code


if __name__ == '__main__':
    main()