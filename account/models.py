from django.db import models

from django.contrib.auth.hashers import make_password

from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager, PermissionsMixin)

# Create your models here.

class UserManager(BaseUserManager):
    def create_user(self, login, password, email, active):
        
        user = self.model(login=login, email=email, active = active)
        user.set_password(password)
        user.save()


class Users(AbstractBaseUser, PermissionsMixin):
    login = models.CharField(unique=True, max_length=20, db_index= True)
    password = models.CharField(max_length=128)
    email = models.CharField(unique=True, max_length=128, db_index= True)
    active = models.BooleanField(default=True)

    USERNAME_FIELD = 'login'
    REQUIRED_FIELDS =['email','password']

    objects = UserManager()

    def __str__(self):
        return str(self.pk)
    
    def samepassword(self):
        return make_password(self.password)
    
    def sameemail(self):
        return self.email
    
    def samelogin(self):
        return self.login
    
    def deactivate(self):
       self.active = 0
       self.save()

    class Meta:
        db_table = 'Users'