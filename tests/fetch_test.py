from ..src.classes.Request import HTTP

def test_can_make_request() -> None:
    r = HTTP.get('https://api.github.com/')
    assert r.status_code == 200
