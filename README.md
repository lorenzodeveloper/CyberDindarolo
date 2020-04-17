# CyberDindarolo

*Disclaimer: This is a project with educational purposes only as it's the result of
"Mobile & Web Applications" class.*

**This is only the backend API of the project, the frontend is available 
<a href="https://github.com/lorenzodeveloper/CyberDindarolo_MobileApp">here</a>.**

It's a simple piggybank (PG) manager application, written in python, using the djangorestframework.

Users can create multiple PGs where they share with other users
(also participating to PG) all the things they bought together.

An user can join a PG only if it's invited by another user, that has already joined the PG, and if the
inviation is accepted.

Each user has a credit for each PG. 
At the start, the credit is zero. Once you start sharing, each time you put something in the PG, your credit 
is going to:

- Increase when inserting a product in the PG;
- decrease when buying something from the PG.

Therefore, the total amount of credit that an user has for each PG is based on the value of things that the user
 put into the shared PG.
 
Each user can see its entry/purchase history.

**Product Insertion Example**

User A inserts 1 pack (50 cones) of Ice Cream Cones (Brand XYZ) bought for 10.00 €. Hence, user A has a total
 credit of 10.00 € that it can use to buy things shared, in the PG.
Each user can buy a single cone at the cost of 0.20 € (10.00 € / 50 pcs).
At the same time, user B buys the same pack of Ice Cream Cones (50 pcs per pack) (Brand XYZ) in a different
 store, spending 15.00 €. Hence, user B has a total credit of 15.00 € that it can use to buy things, shared 
 in the PG.

Now, there are 100 cones in stock. Since the price of the two packs is different, the price for each cone has 
to be calculated using the weighted average price from both `(50 * 0.20 € + 50 * 0.30 €) / 100 = 0.25 €`. 

## Original requirements
- Trust of purchasing history of each user 
- There is a product DB 
- Each user has a credit
- Each user can buy things from PG
- Each user can declare the no: of products bought of each type, resulting in:
    - Changing in price or adding the product
    - Update of user’s credit 
- Each user can see its entry/purchase history

## Assumptions
- There is a PostgreSQL database named "myproject", used by "default_user" with "MyPassword1!" password.
*This could be easily changed, but it is highly recommended that you change the DBMS with one that has
 `REPEATABLE_READ` isolation level.*
- There is a SMTP account available for sending emails (change settings in `settings.py`,
       otherwise the program will crash)

## Dependencies
- **python3** (version used in this project -> 3.7.1)
- **psycopg2** (version used in this project -> 2.8.4)
- **Django** (version used in this project -> 2.2.6)
- **djangorestframework** (version used in this project -> 3.10.3)
- **six** (version used in this project -> 1.12.0)

## Compiling and executing
*Disclaimer: If you’re planning to use it for non-educational purposes, it is recommended to 
change `SECRET_KEY` in `settings.py`.*
*Remember also to set `DEBUG = False`*

Simply run `makemigrations`, `migrate` and `runserver` of `manage.py` module.
```console
$ python manage.py makemigrations
[...]
$ python manage.py migrate
[...]
$ python manage.py runserver
[...]
```

*With `namespace` = `http://localhost:8000/api/v1/` and `REQ_PATH` = `operation that you want to do`:*
You can make all the requests to the API on `namespace/REQ_PATH`

**Example**
- Register user with a `POST` request to `namespace/register/`
- Confirm email
- Login with a `POST` request to `namespace/login/` and store returned `token` somewhere.
- Now you can use this token for all the future requests. *Note: the token will expire in 24h and you will have
to repeat the login.*

**Example of `curl` request after login**
```console
$ curl --location --request GET 'http://localhost:8000/api/v1/users/' \
$ --header 'Authorization: Token 057d61c04f95a283f2fa840af6cc03f5be212256'
[...]
```

See OpenAPI yaml file to get a full view of PG’s instructions and functions.

## OpenAPI 3.0.0 description:

- <a href="https://petstore.swagger.io/?url=https://raw.githubusercontent.com/lorenzodeveloper/CyberDindarolo/master/openapi-schema.yaml">OpenAPI Swagger **DRAFT**</a>

*HTTP_4XX error codes have been omitted, but in general, these are the error codes returned:*

- **400**: *Bad request*         -> missing/invalid input.
- **401**: *Unauthorized*        -> login required or email must be confirmed
- **403**: *Permission denied*   -> depends on the operation (you are trying to insert something in a 
closed PG or you're trying to edit a PG that isn't yours, etc...)
- **404**: 404 not found
- **409**: *Conflict*            -> concurrent operations running

*It can be tested only in a local environment of swagger as I haven't allowed CORS requests.*

## Author
- Lorenzo Fiorani

