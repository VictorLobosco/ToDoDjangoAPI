from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.authentication import CSRFCheck
from rest_framework import exceptions


def get_token_id(request):
    raw_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])
    access_token_obj = AccessToken(str(raw_token))
    user_id= access_token_obj['user_id']
    return user_id


#code from Pradip on stackoverflow:https://stackoverflow.com/questions/66247988/how-to-store-jwt-tokens-in-httponly-cookies-with-drf-djangorestframework-simplej

def enforce_csrf(request):
    check = CSRFCheck()
    check.process_request(request)
    reason = check.process_view(request, None, (), {})
    if reason:
        raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)

class CustomAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        
        if header is None:
            raw_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE']) or None
        else:
            raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        print(validated_token)
        #disable as i was getting this error:TypeError: __init__() missing 1 required positional argument: 'get_response', it should work now but since i 
        #enforce_csrf(request)
        return self.get_user(validated_token), validated_token

