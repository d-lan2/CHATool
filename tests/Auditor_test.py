from http.cookiejar import Cookie
from ..src.services.Auditor import CookieAuditor, HeaderAuditor
from ..src.classes.Output import HeaderResult
from pytest_mock import mocker
import requests 

#Tests written in the AAA format. See HTTP_test.py for more info

def test_can_identify_present_headers(mocker) -> None:
    #Arrange
    fakeResponse =  mocker.MagicMock()
    fakeResponse.headers = {"Content-Security-Policy": "script-src ''" , "X-Content-Type-Options": "nosniff"}
    #Act
    result = HeaderAuditor().analyseHeaders(fakeResponse)

    #Assert
    assert len(result.missingHeaders) == 8
    assert len(result.presentHeaders) == 2


def test_can_identify_present_almost_deprecated_headers(mocker) -> None:
    #Arrange
    fakeResponse =  mocker.MagicMock()
    fakeResponse.headers = {"Feature-Policy": "microphone 'none'; geolocation 'none'" , "Expect-CT": "max-age=86400, enforce, report-uri='https://foo.example/report'"}

    #Act
    result = HeaderAuditor().analyseHeaders(fakeResponse)

    #Assert
    assert len(result.presentAlmostDeprecatedHeaders) == 1
    assert len(result.presentHeaders) == 2

def test_can_identify_present_deprecated_headers(mocker) -> None:
    #Arrange
    fakeResponse =  mocker.MagicMock()
    fakeResponse.headers = {"Public-Key-Pins": "pin-sha256='base64==''; max-age=expireTime [; includeSubDomains][; report-uri='reportURI']" , "X-XSS-Protection": "1; mode=block", "Expect-CT": "max-age=86400, enforce, report-uri='https://foo.example/report'"}

    #Act
    result = HeaderAuditor().analyseHeaders(fakeResponse)

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
    parsedJson = HeaderAuditor().getHeadersJson("somepath")
    #Assert
    assert parsedJson["Some header"] == "Some description"
    assert parsedJson["Some header2"] == "Some description2"

def test_can_correctly_get_missing_headers_data(mocker) -> None:
    #Arrange 
    fakeResults = HeaderResult()
    fakeResults.missingHeaders = ["Content-Security-Policy", "X-Content-Type-Options"]

    #Act
    headersReportData = HeaderAuditor().getHeadersReportData(fakeResults)
    
    #Assert - more of an integration test rather than unit test
    assert headersReportData["Content-Security-Policy"] == "Content Security Policy allows you to whitelist web application resource locations, including where scripts can be loaded from and where the application may be framed. This can therefore mitigate reflected cross-site scripting attacks as well as issues such as Clickjacking."
    assert len(headersReportData) == 2

def test_can_correctly_get_deprecated_headers_data(mocker) -> None:
    #Arrange 
    fakeResults = HeaderResult()
    fakeResults.presentDeprecatedHeaders = ["Public-Key-Pins", "X-XSS-Protection"]

    #Act
    presentheadersReportData = HeaderAuditor().getHeadersReportData(fakeResults)
    
    #Assert - more of an integration test rather than unit test
    assert presentheadersReportData["Public-Key-Pins"] == "WARNING: This header has been deprecated by all major browsers and is no longer recommended. Avoid using it, and update existing code if possible."
    assert len(presentheadersReportData) == 2

def test_can_correctly_get_almost_deprecated_headers_data(mocker) -> None:
    #Arrange 
    fakeResults = HeaderResult()
    fakeResults.presentAlmostDeprecatedHeaders = ["Feature-Policy"]
    #Act
    presentheadersReportData = HeaderAuditor().getHeadersReportData(fakeResults)
    
    #Assert - more of an integration test rather than unit test
    assert presentheadersReportData["Feature-Policy"] == "WARNING: This header was split into Permissions-Policy and Document-Policy and will be considered deprecated once all impacted features are moved off of feature policy. \nThe Feature-Policy header is an experimental feature that allows developers to selectively enable and disable use of various browser features and APIs.The two most well supported values are microphone and camera."
    assert len(presentheadersReportData) == 1

def test_can_identify_cookie_attributes(mocker) -> None:
    #Arrange 
    cookie = Cookie(version=0, name='SID', value='kvm5ds88s5gsggdosg9o1liuj6t52917hmjcd1j1ljv02fgb0snbajanogsommek8opfdcd1mkqmoppm63fa621gai7s78cunkfpn71', port=None, port_specified=False, domain='hack.me', domain_specified=False, domain_initial_dot=False, path='/', path_specified=True, secure=True, expires=1630158864, discard=False, comment=None, comment_url=None, rest={'HttpOnly': None, 'SameSite':'Strict'}, rfc2109=False)
    fakeResponse = mocker.MagicMock()
    fakeResponse.cookies = [cookie]

    #Act
    cookietData = CookieAuditor().getCookieData(fakeResponse)
    
    #Assert 
    assert cookietData.cookies[0].domain == 'hack.me'
    assert cookietData.cookies[0].httpOnly == True
    assert cookietData.cookies[0].lifetime == 1630158864
    assert cookietData.cookies[0].path == '/'
    assert cookietData.cookies[0].sameSite == 'Strict'
    assert cookietData.cookies[0].secure == True

def test_can_recommend_safe_cookie_config(mocker) -> None:
    #Arrange 
    cookie = Cookie(version=0, name='SID', value='kvm5ds88s5gsggdosg9o1liuj6t52917hmjcd1j1ljv02fgb0snbajanogsommek8opfdcd1mkqmoppm63fa621gai7s78cunkfpn71', port=None, port_specified=False, domain='hack.me', domain_specified=False, domain_initial_dot=False, path='/', path_specified=True, secure=True, expires=1630158864, discard=False, comment=None, comment_url=None, rest={'HttpOnly': None, 'SameSite':'Strict'}, rfc2109=False)
    fakeResponse = mocker.MagicMock()
    fakeResponse.cookies = [cookie]

    #Act
    cookietData = CookieAuditor().getCookieData(fakeResponse)
    
    #Assert 
    assert cookietData.cookies[0].domain == 'hack.me'
    assert cookietData.cookies[0].httpOnly == True
    assert cookietData.cookies[0].lifetime == 1630158864
    assert cookietData.cookies[0].path == '/'
    assert cookietData.cookies[0].sameSite == 'Strict'
    assert cookietData.cookies[0].secure == True