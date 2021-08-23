import requests

class HTTP:
    def get(_url, _cookies = None, _headers = None, _data = None, _auth = None):
        return requests.get(_url, cookies=_cookies, headers = _headers, data=_data, auth=_auth)

#checkout this for ms word processing:
#https://python-docx.readthedocs.io/en/latest/

#resume this at 4:20
#https://www.youtube.com/watch?v=f26nAmfJggw