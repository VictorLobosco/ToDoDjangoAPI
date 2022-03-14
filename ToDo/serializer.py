from dataclasses import field
#from pyexpat import model
from rest_framework import serializers
from django.db import models
from .models import Todo
from django.conf import settings


User = settings.AUTH_USER_MODEL

class ToDoSerializer(serializers.ModelSerializer):
    #this piece of code is used to make sure that the user dosent send a empty todo to the database.
    def validate(self, data):
        if not (data.get('name')):
            raise serializers.ValidationError("name field cannot be empyty")
        return data
    class Meta:
        model = Todo
        fields = ['name','details','status', 'user']

        

