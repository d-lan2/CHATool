from ..src.classes.Auditor import Auditor
from ..src.classes.Output import Result
import requests

    #Tests written in the AAA format. See HTTP_test.py for more info
def test_can_identify_present_headers() -> None:
    #Arrange
    fakeResponse =  requests.Response()
    fakeResponse.headers = {"Content-Security-Policy": "script-src ''" , "X-Content-Type-Options": "nosniff"}
    #Act
    result = Auditor().analyseHeaders(fakeResponse)

    #Assert
    assert len(result.missingHeaders) == 12
    assert len(result.presentHeaders) == 2

def test_can_identify_present_almost_deprecated_headers() -> None:
    #Arrange
    fakeResponse =  requests.Response()
    fakeResponse.headers = {"Feature-Policy": "microphone 'none'; geolocation 'none'" , "Expect-CT": "max-age=86400, enforce, report-uri='https://foo.example/report'"}

    #Act
    result = Auditor().analyseHeaders(fakeResponse)

    #Assert
    assert len(result.presentAlmostDeprecatedHeaders) == 2
    assert len(result.presentHeaders) == 2

def test_can_identify_present_deprecated_headers() -> None:
    #Arrange
    fakeResponse =  requests.Response()
    fakeResponse.headers = {"Public-Key-Pins": "pin-sha256='base64==''; max-age=expireTime [; includeSubDomains][; report-uri='reportURI']" , "X-XSS-Protection": "1; mode=block"}

    #Act
    result = Auditor().analyseHeaders(fakeResponse)

    #Assert
    assert len(result.presentDepricatedHeaders) == 2
    assert len(result.presentHeaders) == 2