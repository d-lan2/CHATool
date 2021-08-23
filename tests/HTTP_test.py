from ..src.classes.HTTP import HTTP
import requests

#Tests written in the AAA format
def test_can_make_get_request(mocker) -> None:
    #Arrange - Arrange the test ie set up mocks and expected outputs
    expectedResult = requests.Response()
    expectedResult.status_code = 200

    #Mock actual call to a website with fake response becuase here we are testing our code, not some external site
    mockedRequest = requests.Response()
    mockedRequest.status_code = 200
    mocker.patch('requests.get', return_value=mockedRequest)

    #Act - Ensure the code execution flow is working is expected
    actualResult = HTTP.get('https://doesntexist.secarma.com/')

    #Assert - Check that what we expect to happen is actually happening for the given scenario
    assert actualResult.status_code == expectedResult.status_code

def test_can_make_get_request_with_cookies(mocker) -> None:
    #Arrange
    expectedResult = requests.Response()
    expectedResult.cookies = dict(Cookie="Cookie data")

    mockedRequest = requests.Response()
    mockedRequest.cookies = dict(Cookie="Cookie data")
    mocker.patch('requests.get', return_value=mockedRequest)

    #Act
    cookies = dict(Cookie="Cookie data")
    actualResult = HTTP.get(_url = 'https://doesntexist.secarma.com/', _cookies = cookies)

    #Assert
    assert actualResult.cookies == expectedResult.cookies

def test_can_make_get_request_with_headers(mocker) -> None:
    #Arrange
    expectedResult = requests.Response()
    expectedResult.headers = {'user-agent': 'some-header'}

    mockedRequest = requests.Response()
    mockedRequest.headers = {'user-agent': 'some-header'}
    mocker.patch('requests.get', return_value=mockedRequest)

    #Act
    headers = {'user-agent': 'some-header'}
    actualResult = HTTP.get(_url = 'https://doesntexist.secarma.com/', _headers = headers)

    #Assert
    assert actualResult.headers == expectedResult.headers