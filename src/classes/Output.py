class Result:
    def __init__(self, message = None, errors = None, missingHeaders = [], presentHeaders = [], presentDepricatedHeaders = [], presentAlmostDeprecatedHeaders = []):
        self.message = message
        self.errors = errors
        self.missingHeaders = missingHeaders
        self.presentHeaders = presentHeaders
        self.presentDepricatedHeaders = presentDepricatedHeaders
        self.presentAlmostDeprecatedHeaders = presentAlmostDeprecatedHeaders

    


    