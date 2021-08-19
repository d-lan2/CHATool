from ..src.main import main

#In this case the test function doesnt return anything just calls the assert function
def test_can_access_main() -> None:
    assert main() == 0