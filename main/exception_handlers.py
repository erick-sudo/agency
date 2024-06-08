from rest_framework.views import exception_handler
from rest_framework.exceptions import APIException
from rest_framework import status
from rest_framework.response import Response
from enum import Enum

class FailureCode(Enum):
    """_summary_

    Application failure codes
    
    """
    APPLICATION_ERROR = "An application error occured."
    FAILED_AUTHENTICATION = "Invalid credentials provided."
    MISSING_AUTHENTICATION = "Authentication credentials were not provided."
    ACCOUNT_NOT_VERIFIED = "Account not verified, please verify your account."
    ACCOUNT_ALREADY_VERIFIED = "Account already verified."
    USER_NOT_FOUND = "User not found."
    VALIDATION_ERRORS = "Input validation errors occured please review your inputs and try again."
    PASSWORD_RESET_LINK_INVALID_OR_EXPIRED = "Invalid or expired password reset link. Consider requesting for another."
    INVALID_LINK_TOKEN = "Invalid or expired link"
    

class ApplicationException(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = None
    default_failure_code = FailureCode.APPLICATION_ERROR
    
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
    
def app_exception_handler(exc, context):
    
    # Call default exception handler
    response = exception_handler(exc, context)
    
    if isinstance(exc, ApplicationException):
        
        response_data = {
            'failure': { 'code': exc.failure_code.name, 'description': exc.failure_code.value },
            'detail': exc.detail
        }
        status_code = exc.status_code
        
        return Response(response_data, status=status_code)
    
    return response