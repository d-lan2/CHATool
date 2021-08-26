from ..src.services.Auditor import Auditor
from ..src.classes.Output import Result
from pytest_mock import mocker

#Tests written in the AAA format. See HTTP_test.py for more info

def test_can_identify_present_headers(mocker) -> None:
    #Arrange
    fakeResponse =  mocker.MagicMock()
    fakeResponse.headers = {"Content-Security-Policy": "script-src ''" , "X-Content-Type-Options": "nosniff"}
    #Act
    result = Auditor().analyseHeaders(fakeResponse)

    #Assert
    assert len(result.missingHeaders) == 8
    assert len(result.presentHeaders) == 2


def test_can_identify_present_almost_deprecated_headers(mocker) -> None:
    #Arrange
    fakeResponse =  mocker.MagicMock()
    fakeResponse.headers = {"Feature-Policy": "microphone 'none'; geolocation 'none'" , "Expect-CT": "max-age=86400, enforce, report-uri='https://foo.example/report'"}

    #Act
    result = Auditor().analyseHeaders(fakeResponse)

    #Assert
    assert len(result.presentAlmostDeprecatedHeaders) == 1
    assert len(result.presentHeaders) == 2

def test_can_identify_present_deprecated_headers(mocker) -> None:
    #Arrange
    fakeResponse =  mocker.MagicMock()
    fakeResponse.headers = {"Public-Key-Pins": "pin-sha256='base64==''; max-age=expireTime [; includeSubDomains][; report-uri='reportURI']" , "X-XSS-Protection": "1; mode=block", "Expect-CT": "max-age=86400, enforce, report-uri='https://foo.example/report'"}

    #Act
    result = Auditor().analyseHeaders(fakeResponse)

    #Assert
    assert len(result.presentDeprecatedHeaders) == 3
    assert len(result.presentHeaders) == 3

def test_can_correctly_parse_header_JSON_data_from_file(mocker) -> None:
    #Arrange
    fakeJson = '{"Some header":"Some description", "Some header2":"Some description2"}'
    m = mocker.patch('builtins.open', mocker.mock_open(read_data=fakeJson))
    with open('somepath') as h:
        result = h.read()
            
    #Act
    parsedJson = Auditor().getHeadersJson("somepath")
    #Assert
    assert parsedJson["Some header"] == "Some description"
    assert parsedJson["Some header2"] == "Some description2"

def test_can_correctly_get_missing_headers_data(mocker) -> None:
    #Arrange 
    fakeResults = Result()
    fakeResults.missingHeaders = ["Content-Security-Policy", "X-Content-Type-Options"]

    #Act
    headersReportData = Auditor().getHeadersReportData(fakeResults)
    
    #Assert - more of an integration test rather than unit test
    assert headersReportData["Content-Security-Policy"] == "Content Security Policy allows you to whitelist web application resource locations, including where scripts can be loaded from and where the application may be framed. This can therefore mitigate reflected cross-site scripting attacks as well as issues such as Clickjacking."
    assert len(headersReportData) == 2

def test_can_correctly_get_deprecated_headers_data(mocker) -> None:
    #Arrange 
    fakeResults = Result()
    fakeResults.presentDeprecatedHeaders = ["Public-Key-Pins", "X-XSS-Protection"]

    #Act
    presentheadersReportData = Auditor().getHeadersReportData(fakeResults)
    
    #Assert - more of an integration test rather than unit test
    assert presentheadersReportData["Public-Key-Pins"] == "WARNING: This header has been deprecated by all major browsers and is no longer recommended. Avoid using it, and update existing code if possible."
    assert len(presentheadersReportData) == 2

def test_can_correctly_get_almost_deprecated_headers_data(mocker) -> None:
    #Arrange 
    fakeResults = Result()
    fakeResults.presentAlmostDeprecatedHeaders = ["Feature-Policy"]
    #Act
    presentheadersReportData = Auditor().getHeadersReportData(fakeResults)
    
    #Assert - more of an integration test rather than unit test
    assert presentheadersReportData["Feature-Policy"] == "WARNING: This header was split into Permissions-Policy and Document-Policy and will be considered deprecated once all impacted features are moved off of feature policy. \nThe Feature-Policy header is an experimental feature that allows developers to selectively enable and disable use of various browser features and APIs.The two most well supported values are microphone and camera."
    assert len(presentheadersReportData) == 1