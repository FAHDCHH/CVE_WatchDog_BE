class PipelineException(Exception):
    def __init__(self, message: str = "", cve_id: str | None = None):
        super().__init__(message)
        self.cve_id = cve_id

class URLNotAllowedError(PipelineException):
    pass

class RateLimitError(PipelineException):
    pass

class ExtractionError(PipelineException):
    pass

class CweExtractionError(ExtractionError): pass

class ParseError(PipelineException):
    pass

class StoreError(PipelineException):
    pass

class LoggingError(PipelineException):
    pass

class InvalidLogEventError(LoggingError):
    pass

class R2Error(PipelineException):
    pass

class R2ReadError(R2Error):
    pass

class R2WriteError(R2Error):
    pass

class TransformError(PipelineException):
    pass

class CVSSResolutionError(TransformError):
    pass

class InclusionFilterError(TransformError):
    pass

class EPSSTransformError(TransformError):
    pass

class KEVTransformError(TransformError):
    pass

class CWEResolutionError(TransformError):
    pass

class LoadError(PipelineException):
    pass

class UpsertError(LoadError):
    pass

class HistoryWriteError(LoadError):
    pass

class TransactionError(LoadError):
    pass

class ConsistencyError(PipelineException):
    pass
