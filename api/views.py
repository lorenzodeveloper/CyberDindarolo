import datetime

from django.contrib.auth import authenticate
from django.contrib.auth.models import User as AuthUser
from django.db import IntegrityError
from django.db.models import ExpressionWrapper, DecimalField, BigIntegerField
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK,
    HTTP_201_CREATED, HTTP_403_FORBIDDEN, HTTP_202_ACCEPTED, HTTP_204_NO_CONTENT)

from api.my_helpers import is_blank, is_string_valid_email
from api.models import UserProfile, PiggyBank, Product, Purchase, Entry, Stock, Participate
from api.serializers import UserProfileSerializer, PiggyBankSerializer, ProductSerializer, UserSerializer, \
    EntrySerializer, PurchaseSerializer, StockSerializer


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def login(request):
    """
    An APIview for logging in.
    """
    username = request.data.get("username")
    password = request.data.get("password")
    if username is None or password is None:
        return Response({'error': 'Please provide both username and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=username, password=password)
    if not user:
        return Response({'error': 'Invalid Credentials'},
                        status=HTTP_404_NOT_FOUND)

    # if not user.is_active:
    #     return Response({'error': 'Your account is no longer valid.'},
    #                     status=HTTP_403_FORBIDDEN)

    token, created = Token.objects.get_or_create(user=user)

    utc_now = timezone.now()
    if not created and token.created < utc_now - datetime.timedelta(hours=24):
        token.delete()
        token = Token.objects.create(user=user)
        token.created = timezone.now()
        token.save()

    user.last_login = timezone.now()
    user.save(update_fields=['last_login'])

    return Response({'user_data': UserProfileSerializer(UserProfile.objects.get(auth_user=user)).data,
                     'token': token.key},
                    status=HTTP_200_OK)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticated,))
def logout(request):
    """
    An APIview for logging out.
    """
    request.user.auth_token.delete()
    return Response({'message': 'Succesfully logged out. See you next time.'},
                    status=HTTP_200_OK)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def register(request):
    """
    An APIview for signing up new User instances.
    """
    username = request.data.get("username")
    email = request.data.get("email")
    passwordA = request.data.get("passwordA")
    passwordB = request.data.get("passwordB")
    first_name = request.data.get("first_name")
    last_name = request.data.get("last_name")

    if username is None or passwordA is None or passwordB is None or email is None \
            or first_name is None or last_name is None \
            or is_blank(username) or is_blank(passwordA) or is_blank(passwordB) or is_blank(email) \
            or is_blank(first_name) or is_blank(last_name):
        return Response({'error': 'Please provide username, passwordA_B, email and first/lastname'},
                        status=HTTP_400_BAD_REQUEST)
    # check special chars like ' \ / < > @ ... -> OK, SERIALIZER
    if passwordA != passwordB:
        return Response({'error': 'Passwords must be equal'},
                        status=HTTP_400_BAD_REQUEST)

    if len(passwordA) < 8:
        return Response({'error': 'Password must be 8 chars long or more'},
                        status=HTTP_400_BAD_REQUEST)

    res, ex = is_string_valid_email(email)

    if not res:
        return Response({'error': ex},
                        status=HTTP_400_BAD_REQUEST)

    try:
        user = AuthUser.objects.create_user(username=username, email=email, password=passwordA,
                                            first_name=first_name, last_name=last_name)
        user.save()
    except IntegrityError:
        return Response({'error': 'User already exists'},
                        status=HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': e},
                        status=HTTP_400_BAD_REQUEST)

    # TODO: Send confirmation email to validate user registration
    # TODO: Use UserSerializer to handle user creation

    token, created = Token.objects.get_or_create(user=user)

    user.last_login = timezone.now()
    user.save(update_fields=['last_login'])

    return Response({'user_data': UserProfileSerializer(UserProfile.objects.get(auth_user=user)).data,
                     'token': token.key},
                    status=HTTP_201_CREATED)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticated,))
def get_users_by_pattern(request, pattern):
    """
    An APIview for searching User instances by username or email.
    """

    if not is_blank(pattern) and len(pattern) < 3:
        return Response({'error': 'Pattern must be 3 chars long at least'},
                        status=HTTP_400_BAD_REQUEST)

    valid_email, exc = is_string_valid_email(pattern)
    if valid_email:
        queryset = UserProfile.objects.filter(auth_user__email=pattern,
                                              auth_user__is_active=True).select_related()
    else:
        queryset = UserProfile.objects.filter(auth_user__username__contains=pattern,
                                              auth_user__is_active=True).select_related()

    users = []
    for q in queryset:
        users.append(UserProfileSerializer(q).data)

    if len(users) == 0:
        return Response({'message': 'No users found with that pattern'},
                        status=HTTP_404_NOT_FOUND)

    return Response(users,
                    status=HTTP_200_OK)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticated,))
def get_piggybanks_by_pattern(request, pattern):
    """
    An APIview for searching PiggyBank instances by name.
    """

    if not is_blank(pattern) and len(pattern) < 3:
        return Response({'error': 'Pattern must be 3 chars long at least'},
                        status=HTTP_400_BAD_REQUEST)

    queryset = PiggyBank.objects.filter(pb_name__contains=pattern,
                                        participate__participant__auth_user=request.user).select_related()

    piggybanks = []
    for q in queryset:
        piggybanks.append(PiggyBankSerializer(q).data)

    if len(piggybanks) == 0:
        return Response({'message': 'No piggybanks found with that pattern'},
                        status=HTTP_404_NOT_FOUND)

    return Response(piggybanks,
                    status=HTTP_200_OK)


@permission_classes((IsAuthenticated,))
class PiggyBankViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing PiggyBank instances.
    """
    serializer_class = PiggyBankSerializer
    queryset = PiggyBank.objects.all()
    # Delete is handled apart
    # Verify if permission IsPBOwner works in patch method -> VERIFIED IT DOESN'T WORK
    http_method_names = ['get', 'post', 'patch', 'delete']

    def get_queryset(self):
        queryset = self.queryset
        query_set = queryset.filter(participate__participant__auth_user=self.request.user)
        return query_set

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        data['created_by'] = str(self.request.user.id)
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data,
                        status=HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        piggybank = self.get_object()
        user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
        if piggybank not in user_piggybanks:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)
        piggybank.closed = True
        piggybank.save()
        return Response({'message': 'Piggybank succesfully deleted'},
                        status=HTTP_204_NO_CONTENT)


@permission_classes((IsAuthenticated,))
class ProductViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing Product instances.
    """
    serializer_class = ProductSerializer
    queryset = Product.objects.all()
    # Delete is handled apart -> OK
    http_method_names = ['get', 'post', 'patch', 'delete']

    def destroy(self, request, *args, **kwargs):
        product = self.get_object()
        purchases = Purchase.objects.filter(product=product.id)
        entries = Entry.objects.filter(product=product.id)
        if product in purchases or product in entries:
            return Response({"error": "You don't have the permission to do that."
                                      " The product was entered or bought by someone else"},
                            status=HTTP_403_FORBIDDEN)
        product.delete()
        return Response({'message': 'Product succesfully deleted'},
                        status=HTTP_204_NO_CONTENT)


@permission_classes((IsAuthenticated,))
class UserProfileViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing User instances.
    """
    serializer_class = UserProfileSerializer
    queryset = UserProfile.objects.filter(auth_user__is_active=True)
    # Delete is handled apart -> OK
    # Create user means signup
    http_method_names = ['get', 'patch', 'delete']

    def partial_update(self, request, *args, **kwargs):
        try:
            up_instance = self.queryset.get(pk=kwargs.get('pk'))
        except UserProfile.DoesNotExist as de:
            return Response(status=HTTP_404_NOT_FOUND)

        u_instance = up_instance.auth_user

        if u_instance != request.user:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)

        if request.data.get("piggybanks", None) is not None:
            return Response({"error": "You don't have the permission to do that. "
                                      "Please use specific api request for piggybanks."},
                            status=HTTP_403_FORBIDDEN)

        serializer = UserSerializer(u_instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        resp_data = UserProfileSerializer(UserProfile.objects.get(pk=kwargs.get('pk')))

        return Response(resp_data.data,
                        status=HTTP_202_ACCEPTED)

    def destroy(self, request, *args, **kwargs):
        userprofile = self.get_object()
        if userprofile.auth_user_id != request.user.id:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)
        request.user.is_active = False
        request.user.save()
        token = Token.objects.get(user_id=userprofile.auth_user_id)
        token.delete()
        return Response({'message': 'User succesfully deleted. You\'ll be logged out.'},
                        status=HTTP_204_NO_CONTENT)


@permission_classes((IsAuthenticated,))
class EntryViewSet(viewsets.ModelViewSet):
    """
       A viewset for viewing and editing Entry instances.
       """
    serializer_class = EntrySerializer
    queryset = Entry.objects.filter(entered_by__auth_user__is_active=True)

    http_method_names = ['get', 'post', 'delete']

    def get_queryset(self):
        queryset = self.queryset
        query_set = queryset.filter(entered_by_id=self.request.user.id)
        return query_set

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        piggybank = PiggyBank.objects.get(pk=data['piggybank'])
        user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
        if piggybank not in user_piggybanks:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)
        data['entered_by'] = str(self.request.user.id)
        utc_now = str(timezone.now())
        data['entry_date'] = utc_now
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        from django.db import models
        # The equivalent of a view...
        extended_entry_view = Entry.objects.filter(entered_by=self.request.user.id,
                                                   entry_date=utc_now,
                                                   product=data.get('product'),
                                                   piggybank=data.get('piggybank')).select_related() \
            .annotate(entry__id=models.F('pk')) \
            .annotate(tot_pieces=ExpressionWrapper(models.F('set_quantity') * models.F('product__pieces'),
                                                   output_field=BigIntegerField())) \
            .annotate(tot_cost=ExpressionWrapper(models.F('set_quantity') * models.F('entry_price'),
                                                 output_field=DecimalField(max_digits=6, decimal_places=2))) \
            .annotate(unitary_cost=ExpressionWrapper(models.F('entry_price') / models.F('product__pieces'),
                                                     output_field=DecimalField(max_digits=6, decimal_places=2))) \
            .order_by('entry__id') \
            .values('entry__id', 'entry_date', 'entered_by', 'tot_cost', 'tot_pieces', 'unitary_cost')

        current_stock_in_pb = Stock.objects.filter(piggybank=data.get('piggybank'),
                                                   product=data.get('product')).order_by('-entry_date')

        # If the product is already in stock, simply update stock with new avg price
        # otherwise insert product in stock
        if len(current_stock_in_pb) != 0:
            old_unitary_cost = current_stock_in_pb[0].unitary_price
            old_pieces = current_stock_in_pb[0].pieces

            new_pieces = old_pieces + extended_entry_view[0].get('tot_pieces')
            new_unitary_cost = (old_unitary_cost * old_pieces +
                                extended_entry_view[0].get('tot_cost')) / new_pieces

            new_stock = Stock(piggybank_id=data.get('piggybank'), entry_date=utc_now,
                              entered_by_id=self.request.user.id,
                              product_id=data.get('product'), unitary_price=new_unitary_cost, pieces=new_pieces)
        else:
            new_stock = Stock(piggybank_id=data.get('piggybank'), entry_date=utc_now,
                              entered_by_id=self.request.user.id,
                              product_id=data.get('product'), unitary_price=extended_entry_view[0].get('unitary_cost'),
                              pieces=extended_entry_view[0].get('tot_pieces'))

        participate_instance = Participate.objects.get(participant_id=request.user.id,
                                                       piggybank_id=piggybank.id)
        participate_instance.credit = participate_instance.credit + extended_entry_view[0].get('tot_cost')

        new_stock.save()
        participate_instance.save()

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data,
                        status=HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        entry = self.get_object()
        if entry.entered_by_id != request.user.id:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)
        next_entries = Entry.objects.filter(piggybank_id=entry.piggybank_id,
                                            entry_date__gt=entry.entry_date,
                                            product_id=entry.product_id)
        next_purchases = Purchase.objects.filter(piggybank_id=entry.piggybank_id,
                                                 purchase_date__gt=entry.entry_date,
                                                 product_id=entry.product_id)
        if len(next_entries) != 0 or len(next_purchases) != 0:
            return Response({"error": "There are entries/purchases that depends on this entry. Get rid of those "
                                      "before delete."},
                            status=HTTP_403_FORBIDDEN)

        related_stock = Stock.objects.get(piggybank_id=entry.piggybank_id,
                                          product_id=entry.product_id,
                                          entered_by_id=entry.entered_by_id,
                                          entry_date=entry.entry_date)

        participate_instance = Participate.objects.get(participant_id=entry.entered_by,
                                                       piggybank_id=entry.piggybank_id)
        participate_instance.credit = participate_instance.credit - (entry.entry_price * entry.set_quantity)

        entry.delete()
        related_stock.delete()
        participate_instance.save()

        return Response({'message': 'Entry succesfully deleted.'},
                        status=HTTP_204_NO_CONTENT)


@permission_classes((IsAuthenticated,))
class PurchaseViewSet(viewsets.ModelViewSet):
    """
       A viewset for viewing and editing Purchase instances.
       """
    serializer_class = PurchaseSerializer
    queryset = Purchase.objects.filter(purchaser__auth_user__is_active=True)

    http_method_names = ['get', 'post', 'delete']

    def get_queryset(self):
        queryset = self.queryset
        query_set = queryset.filter(purchaser_id=self.request.user.id)
        return query_set

    def create(self, request, *args, **kwargs):
        data = request.data.copy()
        piggybank = PiggyBank.objects.get(pk=data['piggybank'])
        user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
        if piggybank not in user_piggybanks:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)

        try:
            current_stock_in_pb = Stock.objects.filter(product_id=data.get('product'),
                                                       piggybank=data.get('piggybank')).order_by('-entry_date')[0]
        except IndexError as ie:
            return Response({"error": "Selected product not in stock."},
                            status=HTTP_403_FORBIDDEN)

        data['purchaser'] = str(self.request.user.id)
        utc_now = str(timezone.now())
        data['purchase_date'] = utc_now
        data['unitary_purchase_price'] = current_stock_in_pb.unitary_price
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)

        tot_cost = current_stock_in_pb.unitary_price * int(data.get('pieces'))

        participate_instance = Participate.objects.get(participant_id=request.user.id,
                                                       piggybank_id=piggybank.id)

        if participate_instance.credit - tot_cost < 0 or current_stock_in_pb.pieces - int(data.get('pieces')) < 0:
            return Response({"error": "Credit insufficient or product pieces insufficient."},
                            status=HTTP_403_FORBIDDEN)

        self.perform_create(serializer)

        # if current_stock_in_pb.pieces - int(data.get('pieces')) != 0:
        new_stock = Stock(piggybank_id=data.get('piggybank'), entry_date=utc_now,
                          entered_by_id=self.request.user.id,
                          product_id=data.get('product'), unitary_price=current_stock_in_pb.unitary_price,
                          pieces=(current_stock_in_pb.pieces - int(data.get('pieces'))))
        new_stock.save()
        """else:
            Stock.objects.filter(piggybank_id=data.get('piggybank'),
                                 product_id=data.get('product')).delete()"""

        participate_instance.credit = participate_instance.credit - tot_cost
        participate_instance.save()

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data,
                        status=HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        purchase = self.get_object()
        if purchase.purchaser_id != request.user.id:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)
        next_entries = Entry.objects.filter(piggybank_id=purchase.piggybank_id,
                                            entry_date__gt=purchase.purchase_date,
                                            product_id=purchase.product_id)
        next_purchases = Purchase.objects.filter(piggybank_id=purchase.piggybank_id,
                                                 purchase_date__gt=purchase.purchase_date,
                                                 product_id=purchase.product_id)
        if len(next_entries) != 0 or len(next_purchases) != 0:
            return Response({"error": "There are entries/purchases that depends on this purchase. Get rid of those "
                                      "before delete."},
                            status=HTTP_403_FORBIDDEN)

        related_stock = Stock.objects.get(piggybank_id=purchase.piggybank_id,
                                          product_id=purchase.product_id,
                                          entered_by_id=purchase.purchaser_id,
                                          entry_date=purchase.purchase_date)

        participate_instance = Participate.objects.get(participant_id=purchase.purchaser_id,
                                                       piggybank_id=purchase.piggybank_id)
        participate_instance.credit = participate_instance.credit + (purchase.unitary_purchase_price * purchase.pieces)

        purchase.delete()
        related_stock.delete()
        participate_instance.save()
        return Response({'message': 'Purchase succesfully deleted.'},
                        status=HTTP_204_NO_CONTENT)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticated,))
def get_stock_in_pb(request, piggybank):
    piggybank_inst = PiggyBank.objects.get(pk=piggybank)
    user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
    if piggybank_inst not in user_piggybanks:
        return Response({"error": "You don't have the permission to do that."},
                        status=HTTP_403_FORBIDDEN)
    stock = Stock.objects.filter(piggybank_id=piggybank).order_by('product', '-entry_date').distinct('product')
    serialized_list = []
    for st in stock:
        serialized_list.append(StockSerializer(st).data)
    return Response(serialized_list,
                    status=HTTP_200_OK)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticated,))
def get_prod_stock_in_pb(request, piggybank, product):
    piggybank_inst = PiggyBank.objects.get(pk=piggybank)
    product_inst = Product.objects.get(pk=product)
    user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
    if piggybank_inst not in user_piggybanks:
        return Response({"error": "You don't have the permission to do that."},
                        status=HTTP_403_FORBIDDEN)
    stock = Stock.objects.filter(piggybank=piggybank_inst,
                                 product=product_inst)
    serialized_list = []
    for st in stock:
        serialized_list.append(StockSerializer(st).data)
    return Response(serialized_list,
                    status=HTTP_200_OK)
