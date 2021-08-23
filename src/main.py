"""CHATool Cookie and Header Auditor Tool"""

from requests.models import Response
from src.classes.HTTP import HTTP
from src.classes.Auditor import Auditor


def main():
    response = HTTP.get("https://www.secarma.com/")
    #Auditor.analyseHeaders(response)
    return 0
    

if __name__ == '__main__':
    main()