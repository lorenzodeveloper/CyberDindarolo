# CyberDindarolo

*Disclaimer: This is a project with educational purposes only as it's the result of 
"Mobile & Web Applications" class.*

**This is only the backend API of the project, the frontend will be ready soon and uploaded to another github repo.**

It's a simple piggybank manager application written with python and djangorestframework.

Users can create a piggybank where they share with other users 
(who participate to the pb) all the things they bought together.


## Original requirements
*TODO*

## Assumptions
- There is a PostgreSQL database named "myproject", used by "default_user" with "MyPassword1!" password.
*This could be easily changed* 
- There is an SMTP account available for sending emails (change settings in `settings.py`, 
        otherwise the program will crash)


*TODO*
## Dependencies
- **python3** (version used in this project -> 3.7.1)
- **psycopg2** (version used in this project -> 2.8.4)
- **Django** (version used in this project -> 2.2.6)
- **djangorestframework** (version used in this project -> 3.10.3)
- **six** (version used in this project -> 1.12.0)

*TODO*

## Compiling and executing
Before running the example is recommended to change `SECRET_KEY` in `settings.py` and 
Simply run `makemigrations` and `migrate` of `manage.py` module and runserver.
```console
$ python manage.py makemigrations
[...]
$ python manage.py migrate
[...]
$ python manage.py runserver
[...]
```

Now you can make all the requests to the API on `http://localhost:8000/api/v1/REQ_PATH`, where `REQ_PATH` 
is the operation you want to do.

*With `namespace` = `http://localhost:8000/api/v1/`*

- Register user with a `POST` request to `namespace/register/`
- Confirm email
- Login with a `POST` request to `namespace/login/` and store returned `token` somewhere.
- Now you can use this token for all the future requests. *Note: the token will expire in 24h and you will have
 to repeat the login.*

#### What you can do?
*OpenAPI YAML ready soon*

**DRAFT ONLY AVAILABLE (THERE ARE MANY ERRORS INSIDE IT)**

*TODO*

## Author
- Lorenzo Fiorani
