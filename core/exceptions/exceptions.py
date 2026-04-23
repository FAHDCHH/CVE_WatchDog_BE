class PipelineException(Exception):
    pass

class URLNotAllowedError(PipelineException):
    pass

class RateLimitError(PipelineException):
    pass

class ExtractionError(PipelineException):
    pass

class ParseError(PipelineException):
    pass

class StoreError(PipelineException):
    pass