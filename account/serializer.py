from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from django.db import models
#from django.contrib.auth.models import User
from .models import Users
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ('login','email','password', 'active')
        extra_kwargs = {
            'password':{'write_only': True},
        }

        def hashpass (self, password):
            print(make_password(password))
            return make_password(password)

        
        def save(self, validated_data):
            password = self.make_password(validated_data['password'])
            user = Users.objects.create_user(validated_data['login'], email = validated_data['email'], password = password, active= True)
            return user

# User serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ('login','email','password', 'active')
    
    