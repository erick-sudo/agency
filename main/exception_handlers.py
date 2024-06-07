from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException
from rest_framework import status
from rest_framework.response import Response

class SparkleSyncException(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "Sparkle Sync Exception"
    default_failure_code = "SPARKLE_SYNC_ERROR"
    
    def __init__(self, detail=None, failure_code=None, status_code=None):
        if detail is not None:
            self.detail = detail
        else:
            self.detail = self.default_detail
            
        if failure_code is not None:
            self.failure_code = failure_code
        else:
            self.failure_code = self.default_failure_code
            
        if status_code is not None:
            self.status_code = status_code
        else:
            self.status_code = self.default_status_code
        
    def __str__(self):
        return f"{self.failure_code}: {self.detail}"
    
def sparkle_sync_exception_handler(exc, context):
    
    # Call default exception handler
    response = exception_handler(exc, context)
    
    if isinstance(exc, SparkleSyncException):
        
        response_data = {
            'failure_code': exc.failure_code,
            'detail': exc.detail
        }
        status_code = exc.status_code
        
        return Response(response_data, status=status_code)
    
    return response