#from django.conf.urls import url
from django.urls import path
from .views import RegisterApi, LoginView,  Logout

urlpatterns = [
      path('user/', RegisterApi.as_view()),
      path('login/', LoginView.as_view(), name="login"),
      path('logout/', Logout.as_view(), name='logout'),
]
