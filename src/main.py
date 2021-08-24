"""CHATool Cookie and Header Auditor Tool"""

from requests.models import Response
from classes.HTTP import HTTP
from services.Auditor import Auditor
from services.WordWriter import write


def main():
    print("Welcome to CHATool!")
    print("The Cookie Header Audior Tool")
    write()
    url = input("Input url to scan the security headers:")
    response = HTTP.get(url)
    Auditor.analyseHeaders(response)
    print("Status code:" + str(response.status_code))
    input("Press enter to exit")
    

if __name__ == '__main__':
    main()