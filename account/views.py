
# Create your views here.
from rest_framework import generics
from rest_framework.response import Response
from .serializer import RegisterSerializer
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import RefreshToken, TokenError, AccessToken
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from account.models import Users
from collections import OrderedDict


#gets the user_id inside of the token
def get_token_id(request):
    raw_token = request.COOKIES.get('access_token')
    access_token_obj = AccessToken(str(raw_token))
    user_id= access_token_obj['user_id']
    return user_id

#returns both an acess and a refresh token for a logged user.
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    print(refresh)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
   
#Checks to see if a user has an refresh token, if the anwser is yes it seets the token_status variable to 1.
def checkfortoken(request):
    if request.COOKIES.get('refresh_token'):
        token_status= int(1)
    else:
        token_status = int(0)
    return token_status

    

class RegisterApi(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    def post(self, request, *args,  **kwargs):
        response = Response()
        data = request.data
        #Checks if there is a password in the request data, if there is not one it returns an error
        if 'password' not in data:
            response.data = {"Error": "the password field is required"}
            response.status_code = 400
        #Hashes the password
        data['password'] = make_password(data['password'])
        #Code that checks if all the fields are in place and saves the new user in the database
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            response.data = {"Sucess": "User Created Successfully"}
            response.status_code = 201
            return response
        else:
            response.data = {"Error": serializer.errors}
            response.status_code = 400
            return response
    
    def put(self, request):
        #i am declaring the response variable now as it might be used in the token verification process in the view
        response = Response()
        #This works as both a code that gets the user_id from the acess token and a code that handles the authorization of acess and the creation of a new acess token if the user have a still valid refresh token.
        try:
            # calls get_token_id to if the result is an token error its then checks if the user have an valid refresh token, if it does it generates a new acess token and send-it to the user together with the response from the operation, if it dosent that it deletes the cookies and tells the user to log-in.
            user_id = get_token_id(request)
        except TokenError:
            raw_token = request.COOKIES.get('refresh_token')
            try:
                if raw_token:
                    access_token_obj = RefreshToken(str(raw_token))
                    user_id = access_token_obj['user_id']
                    attrs = OrderedDict()
                    attrs['refresh'] = raw_token
                    tdata = TokenRefreshSerializer.validate(self, attrs=attrs)
                    response.set_cookie(
                                key = settings.SIMPLE_JWT['AUTH_COOKIE'], 
                                value = tdata["access"],
                                expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                                secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                                httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                                samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                        )
                else:
                    response.data = {"Error":"Either your are not logged-in or your login has expired"}
                    #i am deleting cookies here as a secure mesure if the user somehow got any one of thoses tokens without a proper log-in
                    response.delete_cookie('access_token')
                    response.delete_cookie('refresh_token')
                    response.status_code = 401
                    return response
            except:
                    response.data = {"Expired":"Your login have expire please log-in again"}
                    response.delete_cookie('access_token')
                    response.delete_cookie('refresh_token')
                    response.status_code = 401
                    return response

        data = request.data
        #get the data of the currently logged user
        user_data = Users.objects.get(id= int(user_id))
        #does the hashing of the password if there is one in the request.
        if 'password' in data:
            data['password'] = make_password(data['password'])
        #This part of the code checks to see if there is any fields missing in the request, if there are it pulls the one already being used in the database and then it puts in the data variable
        if 'password' not in data:
            data['password'] = user_data.samepassword()
            print(user_data.samepassword())
        if 'login' not in data:
            data['login'] = user_data.samelogin()
        if 'email' not in data:
            data['email'] = user_data.sameemail()
        #Sends the data to the serializer, if the data is valid it saves, if its invalid it returns an error
        serializer = self.get_serializer(user_data, data = data)
        if serializer.is_valid():
            serializer.save()
            response.data = {"Success" : serializer.data}
            response.status_code = 201
            return response
        response.data = {"Error": serializer.errors}
        response.status_code = 400
        return response
    
    def delete(self, request):
        #i am declaring the response variable now as it might be used in the token verification process in the view
        response = Response()
        #This works as both a code that gets the user_id from the acess token and a code that handles the authorization of acess and the creation of a new acess token if the user have a still valid refresh token.
        try:
        # calls get_token_id to if the result is an token error its then checks if the user have an valid refresh token, if it does it generates a new acess token and send-it to the user together with the response from the operation, if it dosent that it deletes the cookies and tells the user to log-in.
            user_id = get_token_id(request)
        except TokenError:
            raw_token = request.COOKIES.get('refresh_token')
            try:
                if raw_token:
                    access_token_obj = RefreshToken(str(raw_token))
                    user_id = access_token_obj['user_id']
                    attrs = OrderedDict()
                    attrs['refresh'] = raw_token
                    tdata = TokenRefreshSerializer.validate(self, attrs=attrs)
                    response.set_cookie(
                                key = settings.SIMPLE_JWT['AUTH_COOKIE'], 
                                value = tdata["access"],
                                expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                                secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                                httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                                samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                        )
                else:
                    response.data = {"Error":"Either your are not logged-in or your login has expired"}
                    #i am deleting cookies here as a secure mesure if the user somehow got any one of thoses tokens without a proper log-in
                    response.delete_cookie('access_token')
                    response.delete_cookie('refresh_token')
                    response.status_code = 401
                    return response
            except:
                    response.data = {"Expired":"Your login have expire please log-in again"}
                    response.delete_cookie('access_token')
                    response.delete_cookie('refresh_token')
                    response.status_code = 401
                    return response
        #get the data of the currently logged user
        user_data = Users.objects.get(id= int(user_id))
        #call upon the deactivate function of the user model and the delete both the acess and the refresh token.
        user_data.deactivate()
        response.data = {{"Deleted":"User Deleted"}}
        response.status_code = 200
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response

#code based on work from Pradip on stackoverflow:https://stackoverflow.com/questions/66247988/how-to-store-jwt-tokens-in-httponly-cookies-with-drf-djangorestframework-simplej
class LoginView(APIView):
    def post(self, request, format=None):
        response = Response()
        #Calls the checkfortoken function to set the value of the token_status variable.
        token_status = checkfortoken(request)
        print(token_status)
        #checks the value of the token_status variable, if its value is 1 it means that the user is already logged in, if the value is 0 its proceeds with the login process
        if token_status == int(0):
            #gets the data in the request, it should contain both login and password in the request, if it dosent the authenticate raises an error.
            data = request.data 
            login = data.get('login', None)
            password = data.get('password', None)
            user = authenticate(login=login, password=password)
            if user is not None:
                #if the user its active it gives both and acess and a refresh token to the user.
                if user.is_active:
                    data = get_tokens_for_user(user)
                    response.set_cookie(
                        key = settings.SIMPLE_JWT['AUTH_COOKIE'], 
                        value = data["access"],
                        expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                        secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                        httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                        samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                    )
                    response.set_cookie(
                        key = settings.SIMPLE_JWT['REFRESH_COOKIE'], 
                        value = data["refresh"],
                        expires = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                        secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                        httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                        samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                    )
                    #csrf.get_token(request)
                    response.data = {"Success" : "Login successfully"}
                    return response
                else:
                    response.data = {"Deactivated" : "This account has been deactivated, if you want to reactivate-it please send a message to an administrator"}
                    response.status_code = 404
                    return response
            else:
                response.data = {"Invalid" : "Invalid username or password!!"}
                response.status_code = 404
                return response
        else:
            response.data = {"Error":"You are already logged in"}
            response.status = 400
            return response


class Logout(generics.GenericAPIView):
    def post(self, request):
        response = Response()
        #calls the checkfortoken function and if the result is 1 its deletes the cookies of the user if its 0 it tells the user to log-in
        token_status = checkfortoken(request)
        if token_status == int(1):
            response.data = {"Logged-out":"you have logged-out"}
            response.status_code = 200
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            return response
        response.data = {"Error":"you need to login to perform this operation"}
        response.status_code = 400
        return response

