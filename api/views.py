import datetime

from django.contrib.auth import authenticate
from django.contrib.auth.models import User as AuthUser
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.mail import send_mail
from django.db import models, transaction, OperationalError
from django.db.models import ExpressionWrapper, DecimalField, BigIntegerField
from django.urls import reverse
from django.utils import timezone
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
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
    HTTP_201_CREATED, HTTP_403_FORBIDDEN, HTTP_202_ACCEPTED, HTTP_204_NO_CONTENT, HTTP_409_CONFLICT,
    HTTP_500_INTERNAL_SERVER_ERROR)

from CyberDindarolo.settings import EMAIL_HOST_USER
from api.authentication import account_activation_token, password_reset_token
from api.models import UserProfile, PiggyBank, Product, Purchase, Entry, Stock, Participate, Invitation
from api.my_helpers import is_blank, is_string_valid_email
from api.permissions import IsAuthenticatedAndEmailConfirmed, HasNotTempPassword
from api.serializers import UserProfileSerializer, PiggyBankSerializer, ProductSerializer, UserSerializer, \
    EntrySerializer, PurchaseSerializer, StockSerializer, InvitationSerializer


# ----------------APIVIEWS / VIEWSETS------------

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

    if not user.userprofile.email_confirmed:
        return Response({'error': 'Must confirm email before login.'},
                        status=HTTP_403_FORBIDDEN)
    utc_now = timezone.now()

    if user.userprofile.password_reset and \
            user.userprofile.password_reset_date < utc_now - datetime.timedelta(hours=24):
        user.is_active = False
        user.save()
        return Response({'error': 'Your temp password is expired and your account will be disabled from now.'
                                  'Contact support to gain access to your account.'},
                        status=HTTP_403_FORBIDDEN)

    token, created = Token.objects.get_or_create(user=user)

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
    An APIView for logging out.
    """
    request.user.auth_token.delete()
    return Response({'message': 'Succesfully logged out. See you next time.'},
                    status=HTTP_200_OK)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def register(request):
    """
    An APIView for signing up new User instances.
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
        return Response({'error': 'Email is not valid.'},
                        status=HTTP_400_BAD_REQUEST)

    users = AuthUser.objects.filter(models.Q(username=username) | models.Q(email=email))
    if len(users) != 0:
        return Response({'error': 'There is already a user with that username/email.'},
                        status=HTTP_400_BAD_REQUEST)
    try:
        with transaction.atomic():
            user = AuthUser.objects.create_user(username=username, email=email, password=passwordA,
                                                first_name=first_name, last_name=last_name)

            # TODO: Use UserSerializer to handle user creation

            # Send email confirmation mail
            send_confirmation_mail(request, user)

            return Response({'message': 'User created, please activate your account by verifying your email.'},
                            status=HTTP_201_CREATED)
    except Exception as e:
        return Response({'error': 'Ops, there was an unexpected error: {}'.format(str(e))},
                        status=HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
def get_users_by_pattern(request, pattern):
    """
    An APIview for searching User instances by username or email.
    """

    if not is_blank(pattern) and len(pattern) < 3:
        return Response({'error': 'Pattern must be 3 chars long at least'},
                        status=HTTP_400_BAD_REQUEST)

    valid_email, exc = is_string_valid_email(pattern)
    if valid_email:
        users = UserProfile.objects.filter(auth_user__email=pattern,
                                           auth_user__is_active=True).select_related()
    else:
        users = UserProfile.objects.filter(auth_user__username__icontains=pattern,
                                           auth_user__is_active=True).select_related()

    users_serialized_list = []
    for u in users:
        data = UserProfileSerializer(u).data
        # Privacy ...
        data.pop("piggybanks")
        users_serialized_list.append(data)

    if len(users_serialized_list) == 0:
        return Response({'message': 'No users found with that pattern'},
                        status=HTTP_404_NOT_FOUND)

    return Response(users_serialized_list,
                    status=HTTP_200_OK)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
def get_piggybanks_by_pattern(request, pattern):
    """
    An APIview for searching PiggyBank instances by name.
    """

    if not is_blank(pattern) and len(pattern) < 3:
        return Response({'error': 'Pattern must be 3 chars long at least'},
                        status=HTTP_400_BAD_REQUEST)

    piggybanks = PiggyBank.objects.filter(pb_name__icontains=pattern,
                                          participate__participant__auth_user=request.user).select_related()

    piggybanks_serialized_list = []
    for pb in piggybanks:
        piggybanks_serialized_list.append(PiggyBankSerializer(pb).data)

    if len(piggybanks_serialized_list) == 0:
        return Response({'message': 'No piggybanks found with that pattern'},
                        status=HTTP_404_NOT_FOUND)

    return Response(piggybanks_serialized_list,
                    status=HTTP_200_OK)


@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
class PiggyBankViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing PiggyBank instances.
    """
    serializer_class = PiggyBankSerializer
    queryset = PiggyBank.objects.all()
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
        return Response({'message': 'Piggybank successfully deleted'},
                        status=HTTP_204_NO_CONTENT)


@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
class ProductViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing Product instances.
    """
    serializer_class = ProductSerializer
    queryset = Product.objects.all()
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
        return Response({'message': 'Product successfully deleted'},
                        status=HTTP_204_NO_CONTENT)


@permission_classes((IsAuthenticatedAndEmailConfirmed,))
class UserProfileViewSet(viewsets.ModelViewSet):
    """
    A viewset for viewing and editing User instances.
    """
    serializer_class = UserProfileSerializer
    queryset = UserProfile.objects.filter(auth_user__is_active=True)
    http_method_names = ['get', 'patch', 'delete']

    def get_queryset(self):
        # A user can see all details only for himself
        queryset = self.queryset
        query_set = queryset.filter(pk=self.request.user)
        return query_set

    def partial_update(self, request, *args, **kwargs):
        try:
            up_instance = self.queryset.get(pk=kwargs.get('pk'))
        except UserProfile.DoesNotExist as de:
            return Response(status=HTTP_404_NOT_FOUND)

        u_instance = up_instance.auth_user

        # Various check
        if u_instance != request.user:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)

        if request.data.get("piggybanks", None) is not None:
            return Response({"error": "You don't have the permission to do that. "
                                      "Please use specific api request for piggybanks."},
                            status=HTTP_403_FORBIDDEN)

        if request.data.get("username", None) is not None:
            return Response({"error": "Can't change your username."},
                            status=HTTP_400_BAD_REQUEST)

        if request.data.get("password", None) is not None:
            return Response({"error": "Please provide passwordA and passwordB to change password."},
                            status=HTTP_400_BAD_REQUEST)
        try:
            # Password change mechanism
            with transaction.atomic():
                passwordA = request.data.get("passwordA", None)
                passwordB = request.data.get("passwordB", None)
                if passwordA is not None and passwordB is not None:
                    if request.data.get("email", None) is not None:
                        return Response({"error": "Can't change password and email at the same time."},
                                        status=HTTP_403_FORBIDDEN)

                    if not up_instance.email_confirmed:
                        return Response({"error": "Can't change password before verifying your email."},
                                        status=HTTP_403_FORBIDDEN)

                    if passwordA != passwordB:
                        return Response({'error': 'Passwords must be equal'},
                                        status=HTTP_400_BAD_REQUEST)
                    if len(passwordA) < 8:
                        return Response({'error': 'Password must be 8 chars long or more'},
                                        status=HTTP_400_BAD_REQUEST)
                    # Set password and save AuthUser instance
                    u_instance.set_password(passwordA)
                    u_instance.save()

                    # Set password reset flag and date to UserProfile instance
                    up_instance.password_reset = False
                    up_instance.password_reset_date = timezone.now()
                    up_instance.save()

                # Save other fields (in request.data)
                serializer = UserSerializer(u_instance, data=request.data, partial=True)
                serializer.is_valid(raise_exception=True)
                serializer.save()

                # Email change mechanism
                new_email = request.data.get("email", None)
                if new_email is not None:

                    old_email = u_instance.email
                    if len(AuthUser.objects.filter(email=new_email)) == 1 \
                            and new_email != old_email:
                        # Set flag and save and mail user
                        up_instance.email_confirmed = False
                        up_instance.save()
                        send_confirmation_mail(request, u_instance)
                    else:
                        raise ValidationError("This email is used by another account / your new_email = your old_email")

                # Return UserProfile JSON
                resp_data = UserProfileSerializer(up_instance)
                return Response(resp_data.data,
                                status=HTTP_202_ACCEPTED)

        except ValidationError as ve:
            return Response({"error": str(ve)},
                            status=HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": "Something bad happened, " + str(e)},
                            status=HTTP_500_INTERNAL_SERVER_ERROR)

    def destroy(self, request, *args, **kwargs):
        userprofile = self.get_object()
        if userprofile.auth_user_id != request.user.id:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)
        # Delete a user = set it to inactive
        request.user.is_active = False
        request.user.save()
        try:
            token = Token.objects.get(user_id=userprofile.auth_user_id)
            token.delete()
        except ObjectDoesNotExist:
            pass
        return Response({'message': 'User successfully deleted. You\'ll be logged out.'},
                        status=HTTP_204_NO_CONTENT)


@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
class EntryViewSet(viewsets.ModelViewSet):
    """
       A viewset for viewing and editing Entry instances.
    """
    serializer_class = EntrySerializer
    queryset = Entry.objects.filter(entered_by__auth_user__is_active=True)

    http_method_names = ['get', 'post', 'delete']

    def get_queryset(self):
        # Entries filtered per active user
        queryset = self.queryset
        query_set = queryset.filter(entered_by_id=self.request.user.id)
        return query_set

    def create(self, request, *args, **kwargs):
        try:
            with transaction.atomic():
                # Get request data copy in order to be able to modify it
                data = request.data.copy()
                request_piggybank = PiggyBank.objects.get(pk=data['piggybank'])
                request_product_id = data.get('product')

                user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
                if request_piggybank not in user_piggybanks:
                    return Response({"error": "You don't have the permission to do that."},
                                    status=HTTP_403_FORBIDDEN)
                if request_piggybank.closed:
                    return Response({"error": "You don't have the permission to do that. Piggybank is closed"},
                                    status=HTTP_403_FORBIDDEN)

                # Set other fields for this request
                data['entered_by'] = str(self.request.user.id)
                utc_now = str(timezone.now())
                data['entry_date'] = utc_now
                serializer = self.get_serializer(data=data)
                serializer.is_valid(raise_exception=True)
                self.perform_create(serializer)

                # Get extended entry
                extended_entry_view = Entry.objects.select_for_update().filter(entered_by=self.request.user.id,
                                                                               entry_date=utc_now,
                                                                               product_id=request_product_id,
                                                                               piggybank=request_piggybank.id) \
                    .annotate(entry__id=models.F('pk')) \
                    .annotate(tot_pieces=ExpressionWrapper(models.F('set_quantity') * models.F('product__pieces'),
                                                           output_field=BigIntegerField())) \
                    .annotate(tot_cost=ExpressionWrapper(models.F('set_quantity') * models.F('entry_price'),
                                                         output_field=DecimalField(max_digits=6, decimal_places=2))) \
                    .annotate(unitary_cost=ExpressionWrapper(models.F('entry_price') / models.F('product__pieces'),
                                                             output_field=
                                                             DecimalField(max_digits=6, decimal_places=2))) \
                    .order_by('entry__id') \
                    .values('entry__id', 'entry_date', 'entered_by', 'tot_cost', 'tot_pieces', 'unitary_cost')

                # If product is in stock, we have to update it
                try:
                    current_stock_in_pb = Stock.objects.select_for_update(). \
                        filter(product_id=request_product_id,
                               piggybank_id=request_piggybank.id).latest('entry_date')
                except ObjectDoesNotExist as oe:
                    current_stock_in_pb = None

                # If the product is already in stock, simply update stock with new avg price
                # otherwise insert product in stock
                if current_stock_in_pb is not None:
                    old_unitary_cost = current_stock_in_pb.unitary_price
                    old_pieces = current_stock_in_pb.pieces

                    new_pieces = old_pieces + extended_entry_view[0].get('tot_pieces')
                    new_unitary_cost = (old_unitary_cost * old_pieces +
                                        extended_entry_view[0].get('tot_cost')) / new_pieces

                    new_stock = Stock(piggybank_id=data.get('piggybank'), entry_date=utc_now,
                                      entered_by_id=self.request.user.id,
                                      product_id=data.get('product'), unitary_price=new_unitary_cost, pieces=new_pieces)
                else:
                    new_stock = Stock(piggybank_id=data.get('piggybank'), entry_date=utc_now,
                                      entered_by_id=self.request.user.id,
                                      product_id=data.get('product'),
                                      unitary_price=extended_entry_view[0].get('unitary_cost'),
                                      pieces=extended_entry_view[0].get('tot_pieces'))

                # Update user credit
                participate_instance = Participate.objects.select_for_update().get(participant_id=request.user.id,
                                                                                   piggybank_id=request_piggybank.id)
                participate_instance.credit = participate_instance.credit + extended_entry_view[0].get('tot_cost')

                # Commit everything
                new_stock.save()
                participate_instance.save()
                # To prevent conflict we need to fake an update of the stock entry
                # (to trigger dirty read problem)
                if current_stock_in_pb is not None:
                    current_stock_in_pb.save()
                headers = self.get_success_headers(serializer.data)
                return Response(serializer.data,
                                status=HTTP_201_CREATED, headers=headers)
        except ObjectDoesNotExist as oe:
            return Response(
                {"error": "Check your input."},
                status=HTTP_400_BAD_REQUEST)

        except OperationalError as e:
            return Response(
                {"error": "Ops, it looks like someone is trying to modify the content of this pb at the "
                          "same time with you. Retry later."},
                status=HTTP_409_CONFLICT)

    def destroy(self, request, *args, **kwargs):
        try:
            with transaction.atomic():
                entry = self.get_object()
                if entry.entered_by_id != request.user.id:
                    return Response({"error": "You don't have the permission to do that."},
                                    status=HTTP_403_FORBIDDEN)

                # If there are entries/purchases that depends on this purchase, we cannot allow the deletion
                next_entries = Entry.objects.select_for_update().filter(piggybank_id=entry.piggybank_id,
                                                                        entry_date__gt=entry.entry_date,
                                                                        product_id=entry.product_id)
                next_purchases = Purchase.objects.select_for_update().filter(piggybank_id=entry.piggybank_id,
                                                                             purchase_date__gt=entry.entry_date,
                                                                             product_id=entry.product_id)
                if len(next_entries) != 0 or len(next_purchases) != 0:
                    return Response(
                        {"error": "There are entries/purchases that depends on this entry. Get rid of those "
                                  "before delete."},
                        status=HTTP_403_FORBIDDEN)
                # Update related stock
                related_stock = Stock.objects.select_for_update().get(piggybank_id=entry.piggybank_id,
                                                                      product_id=entry.product_id,
                                                                      entered_by_id=entry.entered_by_id,
                                                                      entry_date=entry.entry_date)
                # Update user credit
                participate_instance = Participate.objects.select_for_update().get(participant_id=entry.entered_by,
                                                                                   piggybank_id=entry.piggybank_id)
                participate_instance.credit = participate_instance.credit - (entry.entry_price * entry.set_quantity)

                # Commit everything
                entry.delete()
                related_stock.delete()
                participate_instance.save()

                return Response({'message': 'Entry successfully deleted.'},
                                status=HTTP_204_NO_CONTENT)
        except OperationalError as e:
            return Response(
                {"error": "Ops, it looks like someone is trying to modify the content of this pb at the "
                          "same time with you. Retry later."},
                status=HTTP_409_CONFLICT)


@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
class PurchaseViewSet(viewsets.ModelViewSet):
    """
       A viewset for viewing and editing Purchase instances.
    """
    serializer_class = PurchaseSerializer
    queryset = Purchase.objects.filter(purchaser__auth_user__is_active=True)

    http_method_names = ['get', 'post', 'delete']

    def get_queryset(self):
        # Purchases filtered per active user
        queryset = self.queryset
        query_set = queryset.filter(purchaser_id=self.request.user.id)
        return query_set

    def create(self, request, *args, **kwargs):
        try:
            with transaction.atomic():
                # Get request data copy in order to be able to modify it
                data = request.data.copy()
                request_piggybank = PiggyBank.objects.get(pk=data['piggybank'])
                request_product_id = data.get('product')
                request_pieces = int(data.get('pieces'))

                user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
                if request_piggybank not in user_piggybanks:
                    return Response({"error": "You don't have the permission to do that."},
                                    status=HTTP_403_FORBIDDEN)
                if request_piggybank.closed:
                    return Response({"error": "You don't have the permission to do that. Piggybank is closed"},
                                    status=HTTP_403_FORBIDDEN)

                # If product is in stock, we have to update it
                try:
                    current_stock_in_pb = Stock.objects.select_for_update(). \
                        filter(product_id=request_product_id,
                               piggybank_id=request_piggybank.id).latest('entry_date')
                except ObjectDoesNotExist as oe:
                    return Response({"error": "Selected product not in stock."},
                                    status=HTTP_403_FORBIDDEN)

                # Set other fields for this request
                data['purchaser'] = str(self.request.user.id)
                utc_now = str(timezone.now())
                data['purchase_date'] = utc_now
                data['unitary_purchase_price'] = current_stock_in_pb.unitary_price
                serializer = self.get_serializer(data=data)
                serializer.is_valid(raise_exception=True)

                # Calc cost to update purchaser credit
                tot_cost = current_stock_in_pb.unitary_price * request_pieces

                participate_instance = \
                    Participate.objects.select_for_update().get(participant_id=request.user.id,
                                                                piggybank_id=request_piggybank.id)

                if participate_instance.credit - tot_cost < 0 or \
                        current_stock_in_pb.pieces - int(data.get('pieces')) < 0:
                    return Response({"error": "Credit insufficient or product pieces insufficient."},
                                    status=HTTP_403_FORBIDDEN)

                # if current_stock_in_pb.pieces - int(data.get('pieces')) != 0:
                # Add stock update in Stock table
                new_stock = Stock(piggybank_id=request_piggybank.id, entry_date=utc_now,
                                  entered_by_id=self.request.user.id,
                                  product_id=request_product_id, unitary_price=current_stock_in_pb.unitary_price,
                                  pieces=(current_stock_in_pb.pieces - request_pieces))

                """else:
                    Stock.objects.filter(piggybank_id=request_piggybank.id,
                                         request_product_id=request_product_id).delete()"""

                # Update user credit
                participate_instance.credit = participate_instance.credit - tot_cost

                # To prevent conflict we need to fake an update of the stock entry
                current_stock_in_pb.save()

                # Commit everything
                self.perform_create(serializer)
                new_stock.save()
                participate_instance.save()

                headers = self.get_success_headers(serializer.data)
                return Response(serializer.data,
                                status=HTTP_201_CREATED, headers=headers)

        except ObjectDoesNotExist as oe:
            return Response(
                {"error": "Check your input"},
                status=HTTP_400_BAD_REQUEST)

        except OperationalError as e:
            return Response({"error": "Ops, it looks like someone is trying to modify the content of this pb at the "
                                      "same time with you. Retry later."},
                            status=HTTP_409_CONFLICT)

    def destroy(self, request, *args, **kwargs):
        try:
            with transaction.atomic():
                purchase = self.get_object()
                if purchase.purchaser_id != request.user.id:
                    return Response({"error": "You don't have the permission to do that."},
                                    status=HTTP_403_FORBIDDEN)
                # If there are entries/purchases that depends on this purchase, we cannot allow the deletion
                next_entries = Entry.objects.select_for_update().filter(piggybank_id=purchase.piggybank_id,
                                                                        entry_date__gt=purchase.purchase_date,
                                                                        product_id=purchase.product_id)
                next_purchases = Purchase.objects.select_for_update().filter(piggybank_id=purchase.piggybank_id,
                                                                             purchase_date__gt=purchase.purchase_date,
                                                                             product_id=purchase.product_id)
                if len(next_entries) != 0 or len(next_purchases) != 0:
                    return Response(
                        {"error": "There are entries/purchases that depends on this purchase. Get rid of those "
                                  "before delete."},
                        status=HTTP_403_FORBIDDEN)
                # Update the related stock
                related_stock = Stock.objects.select_for_update().get(piggybank_id=purchase.piggybank_id,
                                                                      product_id=purchase.product_id,
                                                                      entered_by_id=purchase.purchaser_id,
                                                                      entry_date=purchase.purchase_date)
                # Update user credit
                participate_instance = Participate.objects.select_for_update().get(participant_id=purchase.purchaser_id,
                                                                                   piggybank_id=purchase.piggybank_id)
                participate_instance.credit = participate_instance.credit + (
                        purchase.unitary_purchase_price * purchase.pieces)

                # Commit everything
                purchase.delete()
                related_stock.delete()
                participate_instance.save()
                return Response({'message': 'Purchase successfully deleted.'},
                                status=HTTP_204_NO_CONTENT)
        except OperationalError as e:
            return Response(
                {"error": "Ops, it looks like someone is trying to modify the content of this pb at the "
                          "same time with you. Retry later."},
                status=HTTP_409_CONFLICT)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
def get_stock_in_pb(request, piggybank):
    """
       An APIView for viewing the stock of a pb instance.
    """
    try:
        request_piggybank = PiggyBank.objects.get(pk=piggybank)
        user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
        if request_piggybank not in user_piggybanks:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)
        stock = Stock.objects.filter(piggybank_id=piggybank).order_by('product', '-entry_date').distinct('product')
        serialized_list = []
        for st in stock:
            serialized_list.append(StockSerializer(st).data)

        return Response(serialized_list,
                        status=HTTP_200_OK)
    except ObjectDoesNotExist as oe:
        return Response(
            {"error": "Check your input, piggybank doesn't exist."},
            status=HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
def get_prod_stock_in_pb(request, piggybank, product):
    """
       An APIView for viewing the stock of a product in pb instance.
    """
    try:
        request_piggybank = PiggyBank.objects.get(pk=piggybank)
        request_product = Product.objects.get(pk=product)
        user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
        if request_piggybank not in user_piggybanks:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)
        stock = Stock.objects.filter(piggybank=request_piggybank,
                                     product=request_product).order_by('product', '-entry_date').distinct('product')
        serialized_list = []
        for st in stock:
            serialized_list.append(StockSerializer(st).data)
        return Response(serialized_list,
                        status=HTTP_200_OK)
    except ObjectDoesNotExist as oe:
        return Response(
            {"error": "Check your input, piggybank and/or product don't/doesn't exist."},
            status=HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
def get_users_in_pb(request, piggybank):
    """
       An APIView for viewing users inside pb..
    """
    try:
        request_piggybank = PiggyBank.objects.get(pk=piggybank)
        user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
        if request_piggybank not in user_piggybanks:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)

        user_inside_pb = UserProfile.objects.filter(participate__piggybank=piggybank)

        serialized_list = []
        for u in user_inside_pb:
            data = UserProfileSerializer(u).data
            # Privacy ...
            data.pop("piggybanks")
            serialized_list.append(data)

        return Response(serialized_list,
                        status=HTTP_200_OK)
    except ObjectDoesNotExist as oe:
        return Response(
            {"error": "Check your input, piggybank doesn't exist."},
            status=HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(["GET"])
@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
def get_products_by_pattern(request, pattern):
    """
       An APIview for searching Product instances by name.
    """
    products = Product.objects.filter(name__icontains=pattern)

    serialized_list = []
    for p in products:
        data = ProductSerializer(p).data
        serialized_list.append(data)

    return Response(serialized_list,
                    status=HTTP_200_OK)


@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
class InvitationViewSet(viewsets.ModelViewSet):
    """
      A viewset for viewing and deleting Invitation instances.
    """
    serializer_class = InvitationSerializer
    queryset = Invitation.objects.all()

    http_method_names = ['get', 'post', 'delete']

    def get_queryset(self):
        # Invitations filtered per user
        queryset = self.queryset
        query_set = queryset.filter(models.Q(inviter_id=self.request.user.id) |
                                    models.Q(invited_id=self.request.user.id)).order_by('-invitation_date')
        return query_set

    def create(self, request, *args, **kwargs):
        # Get request data copy in order to be able to modify it
        data = request.data.copy()
        try:
            request_piggybank = PiggyBank.objects.get(pk=data['piggybank'])
            request_invited = UserProfile.objects.get(pk=data.get('invited'))
        except ObjectDoesNotExist as oe:
            return Response({"error": "Check yur input, user / piggybank not found."},
                            status=HTTP_400_BAD_REQUEST)

        if request.user == request_invited:
            return Response({"error": "Why are you trying to invite yourself to join your pb?"},
                            status=HTTP_403_FORBIDDEN)

        user_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request.user)
        if request_piggybank not in user_piggybanks:
            return Response({"error": "You don't have the permission to do that."},
                            status=HTTP_403_FORBIDDEN)
        if request_piggybank.closed:
            return Response({"error": "You don't have the permission to do that. Piggybank is closed"},
                            status=HTTP_403_FORBIDDEN)

        invited_piggybanks = PiggyBank.objects.filter(participate__participant__auth_user=request_invited)
        if request_piggybank in invited_piggybanks:
            return Response({"error": "User has already joined the pb."},
                            status=HTTP_400_BAD_REQUEST)

        invited_invitations = Invitation.objects.filter(invited=request_invited, piggybank=request_piggybank)
        if len(invited_invitations) != 0:
            return Response({"error": "User was already invited to join the pb."},
                            status=HTTP_400_BAD_REQUEST)

        data['inviter'] = str(request.user.id)
        utc_now = str(timezone.now())
        data['invitation_date'] = utc_now
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data,
                        status=HTTP_201_CREATED, headers=headers)

    # TODO: Check if this method is necessary or not
    def destroy(self, request, *args, **kwargs):
        try:
            with transaction.atomic():
                invitation = self.get_object()
                if invitation.inviter_id != request.user.id:
                    return Response({"error": "You don't have the permission to do that."},
                                    status=HTTP_403_FORBIDDEN)
                invitation.delete()
                return Response({'message': 'Invitation successfully deleted.'},
                                status=HTTP_204_NO_CONTENT)

        except OperationalError as e:
            return Response(
                {"error": "Ops, it looks like someone is trying to modify the invitation at the "
                          "same time with you. Retry later."},
                status=HTTP_409_CONFLICT)


@csrf_exempt
@api_view(["POST"])
@permission_classes((IsAuthenticatedAndEmailConfirmed, HasNotTempPassword,))
def manage_invitation(request, invitation):
    """
       An APIview for managing invitation (accept or decline).
    """
    try:
        with transaction.atomic():
            invitation = Invitation.objects.select_for_update().get(pk=invitation)
            accept = request.data.get('accept', 0)  # Default is 0 = Decline

            if invitation.invited_id != request.user.id:
                return Response({"error": "You don't have the permission to do that."},
                                status=HTTP_403_FORBIDDEN)

            if accept != 0:
                # Accept invitation
                participate = Participate(participant_id=request.user.id,
                                          piggybank_id=invitation.piggybank.id)
                participate.save()

            invitation.delete()

            return Response({'message': 'Invitation successfully accepted/declined.'},
                            status=HTTP_202_ACCEPTED)

    except ObjectDoesNotExist as oe:
        return Response(
            {"error": "Check your input, invitation doesn't exist."},
            status=HTTP_400_BAD_REQUEST)

    except OperationalError as e:
        return Response(
            {"error": "Ops, it looks like someone is trying to modify the invitation at the "
                      "same time with you. Retry later."},
            status=HTTP_409_CONFLICT)


# ---------------------EMAIL METHODS----------------------

def send_token_email(request, user, token_gen, viewname, subject, html_message):
    """
    This method send a one time link to the user with the token_gen passed.

    :param user: AuthUser instance to send the email
    :param token_gen: token generator
    :param subject: Email subject
    :param html_message: html message
    """
    token = token_gen.make_token(user)

    link = request.build_absolute_uri(reverse(viewname, kwargs={
        'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': str(token)}
                                              ))

    html_message = html_message.format(user.first_name, link)

    message = html_message.replace("<br>", "\n"). \
        replace("<a href=\'", ""). \
        replace("\'>", ""). \
        replace("</a>", "")

    send_mail(subject=subject, message=message, html_message=html_message,
              from_email=EMAIL_HOST_USER, recipient_list=[user.email], fail_silently=False)


def send_confirmation_mail(request, user):
    """
    This method send an email to the user to verify his email account.

    :param user: AuthUser instance
    """
    html_message = 'Welcome {},<br>Please click on the link to activate your account.<br><br>Link:<br>' \
                   '<a href=\'{}\'>Verify</a>'
    send_token_email(request, user, account_activation_token, 'verify_account',
                     'CyberDindarolo email verification', html_message)


@csrf_exempt
@api_view(["GET"])
@permission_classes((AllowAny,))
def confirm_email(request, uidb64, token):
    """
    This APIView send a one time link to the user mail to verify his mail.

    :param uidb64: user identifier in base64
    :param token: one time token for email confirmation
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = AuthUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, ObjectDoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.userprofile.email_confirmed = True
        user.userprofile.save()
        return Response({'message': 'Account successfully verified.'},
                        status=HTTP_202_ACCEPTED)
    else:
        # invalid link
        return Response({'error': 'Invalid link'},
                        status=HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(["GET"])
@permission_classes((AllowAny,))
def reset_password(request, uidb64, token):
    """
    This APIView assigns a temporary password to the user and send it to him via mail.

    :param uidb64: user identifier in base64
    :param token: one time token for password change
    """
    if not request.user.is_anonymous:
        return Response({"error": "You don't have the permission to do that. Logout before doing this."},
                        status=HTTP_403_FORBIDDEN)
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = AuthUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, ObjectDoesNotExist):
        user = None

    if user is not None and password_reset_token.check_token(user, token):
        # Generate alphanumeric random pwd
        tmp_password = AuthUser.objects.make_random_password()
        user.set_password(tmp_password)
        user.save()

        # Set password reset flag and datetime
        user.userprofile.password_reset = True
        user.userprofile.password_reset_date = timezone.now()
        user.userprofile.save()

        # Send mail
        message = "Hi {},\nUse this password to login into your CyberDindarolo account and " \
                  "immediately change password\n\n{}\n\nNote: You have 24 hours to login and change " \
                  "your password, after that your account will be " \
                  "disabled for security reason.".format(user.first_name, tmp_password)
        html_message = message.replace("\n", "<br>")

        send_mail(subject='CyberDindarolo password reset confirmation', message=message, html_message=html_message,
                  from_email=EMAIL_HOST_USER, recipient_list=[user.email], fail_silently=False)

        return Response({'message': 'Password successfully reset, change password immediately '
                                    'in order to gain access in future.'},
                        status=HTTP_202_ACCEPTED)
    else:
        # invalid link
        return Response({'error': 'Invalid link'},
                        status=HTTP_400_BAD_REQUEST)


@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def forgot_password(request):
    """
    This APIView send an email to the user to reset his password.
    """
    if not request.user.is_anonymous:
        return Response({"error": "You don't have the permission to do that. Logout before doing this."},
                        status=HTTP_403_FORBIDDEN)
    email = request.data.get("email", None)
    if email is None:
        return Response({"error": "Email is required."},
                        status=HTTP_400_BAD_REQUEST)
    try:
        user = AuthUser.objects.get(email=email)
    except ObjectDoesNotExist as oe:
        user = None

    if user is None:
        return Response({"error": "No user with this email found."},
                        status=HTTP_400_BAD_REQUEST)

    if not user.userprofile.email_confirmed:
        return Response({"error": "You can't reset your password before verifying your account."},
                        status=HTTP_403_FORBIDDEN)

    # If user has requested a password reset in the last 24 hours
    if user.userprofile.password_reset or user.userprofile.password_reset_date >= \
            timezone.now() - timezone.timedelta(hours=24):
        return Response({"error": "You already did a password change,"
                                  " check your email or wait 24h to repeat this procedure."},
                        status=HTTP_403_FORBIDDEN)

    # Send one time link password reset via mail
    html_message = "Welcome {},<br>Please click on the link to reset your password.<br><br>Link:<br>" \
                   "<a href=\'{}\'>Reset Password</a><br><br>You did not request a password reset? " \
                   "Simply ignore this email."
    send_token_email(request, user, password_reset_token, 'reset_password',
                     'CyberDindarolo password reset', html_message)

    try:
        # Delete current token if exist
        token = Token.objects.get(user=user)
        token.delete()
    except ObjectDoesNotExist:
        pass

    return Response({"message": "Sent email for password reset."},
                    status=HTTP_200_OK)
