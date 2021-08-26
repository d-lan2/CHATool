"""CHATool Cookie and Header Auditor Tool"""

from requests.models import Response
from src.classes.HTTP import HTTP
from src.services.Auditor import Auditor
from src.services.WordWriter import WordWriter


def main():
    print("Welcome to CHATool!")
    print("The Cookie Header Audior Tool")
    url = input("Input url to scan the security headers:")
    response = HTTP.get(url)
    results = Auditor().analyseHeaders(response)
    WordWriter().writeDoc(results, "output\\test3.docx")
    print("Status code:" + str(response.status_code))
    input("Press enter to exit")
    

if __name__ == '__main__':
    main()