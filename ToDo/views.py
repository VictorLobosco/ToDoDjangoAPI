from django.conf import settings
from rest_framework import generics
from ToDo.models import Todo
from ToDo.serializer import ToDoSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import TokenError, RefreshToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from collections import OrderedDict
from account.views import get_token_id



class ToDo_Main(generics.GenericAPIView):
    def get(self, request):
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
        #gets all Todos that are owned by the user and then returns it to the user
        todos = Todo.objects.filter(user_id = user_id)
        serializer = ToDoSerializer(todos, many=True)
        response.data = {"ToDo": serializer.data}
        response.status_code = 200
        return response


    def post(self, request):
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
        #manually sets the user value inside of the request data to the user_id
        data["user"] = (str(user_id))
        # some default values so there are not set to null in the database
        if data:
                if 'details' not in data:
                    data['details'] = "none"
                if 'status' not in data:
                    data['status'] = "pending"
        #pass the data to the serializer and checks if its valid, if the data is valid it saved and then return to the user if its not the error from the serializer is return to the user.
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
        #gets the Todo with the sent id
        todo = Todo.objects.filter(id = id)
        #filter on the already filter query to check if there is any entrys with that id owned by the user
        ntodo = todo.filter(user_id = int(user_id))
        #checks if the result of the filtering is not none, if it is it means that there are no entrys in the database with that id that are owned by the user, if that is the case an message is sent to the user informing that
        if not ntodo:
            response.data = {'Not Found': "no entry with this id is owned by the user"}
            response.status_code = 404
            return response
        #if the user is the owner of the todo that data is return to the user.
        serializer = ToDoSerializer(ntodo, many=True)
        response.data = serializer.data
        response.status_code = 200
        return response


    def put(self, request, id):
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
                    response.data = {"Error":"Either your are not logged-in or your login has expired"}
                    #i am deleting cookies here as a secure mesure if the user somehow got any one of thoses tokens without a proper log-in
                    response.delete_cookie('access_token')
                    response.delete_cookie('refresh_token')
                    response.status_code = 401
                    return response
        data = request.data
        todo_id = int(id)
        #sets the user field in the request data to be the same as the user_id
        data["user"] = (str(user_id))
        #this is used to know if the entry exists
        todo = Todo.objects.filter(id = todo_id)
        #filter on the already filter query to check if there is any entrys with that id owned by the user
        ntodo = todo.filter(user_id = int(user_id))
        #checks if the result of the filtering is not none, if it is it means that there are no entrys in the database with that id that are owned by the user, if that is the case an message is sent to the user informing that
        if not ntodo:
            response.data = {'Not Found': "no entry with this id is owned by the user"}
            response.status_code = 404
            return response
        #gets the data of the entry with the giben id
        todo_data = Todo.objects.get(id = todo_id)
        #if there is no name field in the data the samename method is called from the model to set the same data that was already being used to the field
        if 'name' not in data:
            data['name'] = todo_data.samename()
            print(todo_data.samename())
        #if there is no details field in the data the samedetails method is called from the model to set the same data that was already being used to the field
        if 'details' not in data:
            data['details'] = todo_data.samedetails()
        #if there is no status field in the data the samestatus method is called from the model to set the same data that was already being used to the field
        if 'status' not in data:
            data['status'] = todo_data.samestatus()
        #sends the data to the serializer and then check if its valid, if it is the changes are saved and return to the user, if its not then the serializer errors are return to the user insted.
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
    
        #this is used to know if the entry exists
        todo = Todo.objects.filter(id = id)
        #filter on the already filter query to check if there is any entrys with that id owned by the user
        ntodo = todo.filter(user_id = int(user_id))
        #checks if the result of the filtering is not none, if it is it means that there are no entrys in the database with that id that are owned by the user, if that is the case an message is sent to the user informing that
        if not ntodo:
            response.data = {'Not Found': "No entry with this id is owned by the user"}
            response.status_code = 404
            return response
        #if the user owns the Todo with that id the .delete method is called and the todo is deleted
        todo.delete()
        response.data = {'Deleted': "Entry deleted"}
        response.status_code = 204
        return response





