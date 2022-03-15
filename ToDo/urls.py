#from django.conf.urls import url
from django.urls import path
from .views import ToDo_Main, Todo_Byid

urlpatterns = [
      path('todo/', ToDo_Main.as_view()),
      path('todobyid/<int:id>', Todo_Byid.as_view() )

]