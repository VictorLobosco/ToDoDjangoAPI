from django.db import models
from django.conf import settings
# Create your models here.

User = settings.AUTH_USER_MODEL

class Todo(models.Model):
    name = models.CharField(max_length=80, blank=True, null=True)
    details = models.CharField(max_length=250, blank=True, null=True)
    status = models.CharField(max_length=200, blank=True, null=True)
    user = models.ForeignKey(User,on_delete=models.CASCADE)


    def samename(self):
        return self.name
    
    def samedetails(self):
        return self.details
    
    def samestatus(self):
        return self.status





    class Meta:
        db_table = 'todo'