from ..lib.classes.Auditor import Auditor
from ..lib.classes.Output import Result
import requests

class TestClass:
    result = Result()

    def setup_method(self, method):
        self.result = None
    
    def teardown_method(self, method):
        self.result = None

    #Tests written in the AAA format. See HTTP_test.py for more info
    def test_can_identify_present_headers(self) -> None:
        #Arrange
        fakeResponse =  requests.Response()
        fakeResponse.headers = {"Content-Security-Policy": "script-src 'self'" , "X-Content-Type-Options": "nosniff"}
        #Act
        self.result = Auditor().analyseHeaders(fakeResponse)

        #Assert
        assert len(self.result.missingHeaders) == 12
        assert len(self.result.presentHeaders) == 2

    def test_can_identify_present_almost_deprecated_headers(self) -> None:
        #Arrange
        fakeResponse =  requests.Response()
        fakeResponse.headers = {"Feature-Policy": "microphone 'none'; geolocation 'none'" , "Expect-CT": "max-age=86400, enforce, report-uri='https://foo.example/report'"}

        #Act
        self.result = Auditor().analyseHeaders(fakeResponse)

        #Assert
        assert len(self.result.presentAlmostDeprecatedHeaders) == 2
        assert len(self.result.presentHeaders) == 2

    def test_can_identify_present_deprecated_headers(self) -> None:
        #Arrange
        fakeResponse =  requests.Response()
        fakeResponse.headers = {"Public-Key-Pins": "pin-sha256='base64==''; max-age=expireTime [; includeSubDomains][; report-uri='reportURI']" , "X-XSS-Protection": "1; mode=block"}

        #Act
        self.result = Auditor().analyseHeaders(fakeResponse)

        #Assert
        assert len(self.result.presentDepricatedHeaders) == 2
        assert len(self.result.presentHeaders) == 2