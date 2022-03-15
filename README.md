# ToDoDjangoAPI
A port and improvement to Django rest-framework of my Flask rest-api

# What you will need to run this code

- python

- Django

- DjangoRestFramework

- djangorestframework-simplejwt

- psycopg2-binary


# How it works

The layout of this project is very similiar to the flask version, the main diference is that the way a new acess token is issued to the user, in this version i use
a code that run before each view that checks if the user has an non expired valid acess token, if the acess token is expired it then checks to see if the user has an
refresh token that is still valid, if it has a new acess token is created an sent with the response of the view, if the user dosent have an valid refresh token the api deletes all instances of
an acess and refresh token and then tell the user to log-in again.

- account/user/

  Parameters: login, password and email [All obligatory for a POST request]

  This route does the registration of an user using POST, it uses PUT to change info to a registered user and uses DELETE to disable access of a user by changing the   account to inactive in the database
  
- /account/login/

  Parameters: login and password

  This route is used to get an token to access the database

- /account/logout/

  Parameters: none
  
  This route deletes all cookies related to the API

- /todo/todo/

  Parameters: name [Obligatory for POST], details and status

  This route takes care of both creating a todo by sending a request with POST and displaying all the ToDos owned by the currently logged user by sending a GET      request

- /todo/todobyid/id/

  Parameters: name, details and status

  This route's GET method displays an specific ToDo by using its id as an identifier, it allows to modify an ToDo by using the passed id by sending an PUT request and lastly it allows to Delete an ToDo by sending an DELETE request, as long as the ToDo with the sent ID belongs to the currently logged-in user
