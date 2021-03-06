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
router.register(r'invitations', views.InvitationViewSet, basename='invitation')

urlpatterns = [

    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('register/', views.register, name='register'),

    path('', include(router.urls)),

    re_path('^users/search/(?P<pattern>[-a-zA-Z0-9_@.]{1,254})/$', views.get_users_by_pattern,
            name='search_user'),
    re_path('^piggybanks/search/(?P<pattern>[- a-zA-Z0-9_@.]{1,254})/$', views.get_piggybanks_by_pattern,
            name='search_piggybank'),

    re_path('^products/search/(?P<pattern>[- a-zA-Z0-9_@.]{1,254})/$', views.get_products_by_pattern,
            name='search_product'),

    path('stock/<int:piggybank>/', views.get_stock_in_pb, name='stock_pb'),
    path('stock/<int:piggybank>/<int:product>/', views.get_prod_stock_in_pb, name='prod_stock_pb'),

    path('credit/<int:piggybank>/', views.get_credit_in_pb, name='credit_pb'),
    path('users/inside/<int:piggybank>/', views.get_users_in_pb, name='users_pb'),

    path('invitations/manage/<int:invitation>/', views.manage_invitation, name='manage_invitation'),

    re_path(r'^verify_account/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
            views.confirm_email, name='verify_account'),

    path('forgot_password/', views.forgot_password, name='forgot_password'),
    re_path(r'^reset_password/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
            views.reset_password, name='reset_password'),

    # insert new piggybank                                            -> OK
    # insert new product (PRODUCT TABLE)                              -> OK
    # insert entry (product in piggybank with price)                  -> OK
    # insert purchase                                                 -> OK

    # invite user to join                                             -> OK
    # accept or decline invitation                                    -> OK

    # delete piggybank: close piggybank (no one cannot add entry or purchase to that pb) -> OK

    # search piggybank by name -> returns pb_ID                       -> OK
    # search product by name -> returns prod_ID                       -> OK

    # get user profile info by id                                     -> OK
    # get users in piggybank                                          -> OK
    # get invitations of user
    # get purchases in piggybank                                      -> OK
    # get entries in piggybank                                        -> OK
    # get stock of piggybank                                          -> OK

    # edit user infos                                                  -> OK
    # edit product                                                     -> OK
    # edit piggybank                                                   -> OK

    # remove entry (only if the entered product wasn't bought by anyone in pb)    -> OK
    # remove purchase (only the last one and if the purchased product was not refilled meanwhile) -> OK
    #       In this way we avoid edit entry/purchase
    #  remove product (only if the entered product wasn't bought by anyone in any pb) -> OK
]
