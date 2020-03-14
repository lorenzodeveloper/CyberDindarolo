"""CyberDindarolo URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path, re_path, include
from rest_framework.routers import DefaultRouter

from api import views


router = DefaultRouter()
router.register(r'piggybanks', views.PiggyBankViewSet, basename='piggybank')
router.register(r'products', views.ProductViewSet, basename='product')
router.register(r'users', views.UserProfileViewSet, basename='user')
router.register(r'entries', views.EntryViewSet, basename='entry')
router.register(r'purchases', views.PurchaseViewSet, basename='purchase')


urlpatterns = [

    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('register/', views.register, name='register'),

    path('', include(router.urls)),

    re_path('users/search/(?P<pattern>[-a-zA-Z0-9_@.]{3,254})', views.get_users_by_pattern,
            name='search_user'),
    re_path('piggybanks/search/(?P<pattern>[-a-zA-Z0-9_@.]{3,254})', views.get_piggybanks_by_pattern,
            name='search_piggybank'),

    path('stock/<int:piggybank>/', views.get_stock_in_pb, name='stock_pb'),
    path('stock/<int:piggybank>/<int:product>/', views.get_prod_stock_in_pb, name='prod_stock_pb'),

    path('users/inside/<int:piggybank>/', views.get_users_in_pb, name='users_pb'),


    # TODO: insert new piggybank                                            -> OK
    # TODO: insert new product (PRODUCT TABLE)                              -> OK
    # TODO: insert entry (product in piggybank with price)                  -> OK
    # TODO: insert purchase                                                 -> OK

    # TODO: invite user to join piggybank
    # TODO: accept or decline invitation

    # TODO: delete piggybank: close piggybank (no one cannot add entry or purchase to that pb) -> OK

    # TODO: search piggybank by name -> returns pb_ID                       -> OK
    # TODO: search product by name -> returns prod_ID


    # TODO: get user profile info by id -> returns everything except pwd    -> OK
    # TODO: get users in piggybank                                          -> OK
    # TODO: get invitations of user
    # TODO: get purchases in piggybank                                      -> OK
    # TODO: get entries in piggybank                                        -> OK
    # TODO: get stock of piggybank

    # TODO: edit user infos                                                  -> ALMOST OK (change password mechanism)
    # TODO: edit product                                                     -> OK
    # TODO: edit piggybank                                                   -> OK


    # TODO: remove entry (only if the entered product wasn't bought by anyone in pb)    -> OK
    # TODO: remove purchase (only the last one and if the purchased product was not refilled meanwhile) -> OK
    #       In this way we avoid edit entry/purchase
    # TODO: remove product (only if the entered product wasn't bought by anyone in any pb) -> OK
]
