from django.conf import settings

# Create your views here.
from rest_framework import generics

from ToDo import serializer
from rest_framework.views import APIView
import ToDo
from ToDo.models import Todo
from ToDo.serializer import ToDoSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import AccessToken, TokenError, RefreshToken
from rest_framework_simplejwt import authentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenVerifyView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from collections import OrderedDict
from account.authenticate import enforce_csrf
from rest_framework.authentication import CSRFCheck
from rest_framework import exceptions






from account.views import get_token_id


#I NEED TO START DOCUMENTING THIS FILE AND CHECK IF THE AUTHENTICATION FILE IS STILL NEEDED!!!!!!!!

class ToDo_Main(generics.GenericAPIView):
    def get(self, request):
        response = Response()
        try:
            user_id = get_token_id(request)
        except TokenError:
            raw_token = request.COOKIES.get('refresh_token')
            #raw_token = request.COOKIES.get('refresh_token')
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
                    #i am deleting cookies here as a security mesure if the user somehow got any one of thoses tokens without a proper log-in
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
        todos = Todo.objects.filter(user_id = user_id)
        serializer = ToDoSerializer(todos, many=True)
        response.data = {"ToDo": serializer.data}
        response.status_code = 200
        #enforce_csrf(self, response)
        return response


    def post(self, request):
        response = Response()
        try:
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
                    #i am deleting cookies here as a security mesure if the user somehow got any one of thoses tokens without a proper log-in
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
        data["user"] = (str(user_id))
        if data:
                if 'details' not in data:
                    data['details'] = "none"
                if 'status' not in data:
                    data['status'] = "pending"
        serializer = ToDoSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            response.data = {"ToDo": serializer.data}
            response.status_code = 201
            return response
        response.data = {"Error": serializer.errors}
        response.status_code = 400
        return response


class Todo_Byid(generics.GenericAPIView):
    def get(self, request, id):
        response = Response()
        try:
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
                    #i am deleting cookies here as a security mesure if the user somehow got any one of thoses tokens without a proper log-in
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
        
        todo = Todo.objects.filter(id = id)
        #filter on the already filter query to check if there is any entrys with that id owned by the user
        ntodo = todo.filter(user_id = int(user_id))
        serializer = ToDoSerializer(ntodo, many=True)
        if not ntodo:
            response.data = {'Not Found': "no entry with this id is owned by the user"}
            response.status_code = 404
            return response

        response.data = serializer.data
        response.status_code = 200
        return response


    def put(self, request, id):
        response = Response()
        try:
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
                    response.data = {"Error":"Either your are not logged-in or your login has expired"}
                    #i am deleting cookies here as a secure mesure if the user somehow got any one of thoses tokens without a proper log-in
                    response.delete_cookie('access_token')
                    response.delete_cookie('refresh_token')
                    response.status_code = 401
                    return response
        data = request.data
        todo_id = int(id)
        data["user"] = (str(user_id))
        #this is used to know if the entry exists
        todo = Todo.objects.filter(id = todo_id)
        #filter on the already filter query to check if there is any entrys with that id owned by the user
        ntodo = todo.filter(user_id = int(user_id))
        if not ntodo:
            response.data = {'Not Found': "no entry with this id is owned by the user"}
            response.status_code = 404
            return response
        todo_data = Todo.objects.get(id = todo_id)
        if 'name' not in data:
            data['name'] = todo_data.samename()
            print(todo_data.samename())
        if 'details' not in data:
            data['details'] = todo_data.samedetails()
        if 'status' not in data:
            data['status'] = todo_data.samestatus()
        #print(todo_data.content)
        serializer = ToDoSerializer(todo_data, data = data)
        if serializer.is_valid():
            serializer.save()
            response.data = serializer.data
            response.status_code = 201
            return response

        response.data = serializer.errors
        response.status_code = 400
        return response
    
    def delete(self, request, id):
        #try:
        response = Response()
        try:
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
    
        #this is used to know if the entry exists
        todo = Todo.objects.filter(id = id)
        #filter on the already filter query to check if there is any entrys with that id owned by the user
        ntodo = todo.filter(user_id = int(user_id))
        if not ntodo:
            response.data = {'Not Found': "No entry with this id is owned by the user"}
            response.status_code = 404
            return response
        todo.delete()
        response.data = {'Deleted': "Entry deleted"}
        response.status_code = 204
        return response





