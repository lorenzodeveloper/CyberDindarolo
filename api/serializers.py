from django.contrib.auth.models import User as AuthUser
from rest_framework import serializers

from api.models import UserProfile, PiggyBank, Product, Entry, Purchase, Stock, Invitation, Participate
from api.my_helpers import is_string_valid, is_string_valid_un


class UserSerializer(serializers.ModelSerializer):
    def validate(self, data):
        """
        Check that first_name, last_name and username are valid strings.
        """
        if not is_string_valid(data.get("first_name")) or not is_string_valid(data.get("last_name")) \
                or not is_string_valid_un(data.get("username")):  # or \
            # (data.get("email") is not None and not is_string_valid_email(data.get("email"))):
            raise serializers.ValidationError({"error": "Check your input."})
        return data

    class Meta:
        model = AuthUser
        fields = ['id', 'username', 'first_name', 'last_name', 'email']


class UserProfileWithoutPBSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='auth_user.username')
    first_name = serializers.CharField(source='auth_user.first_name')
    last_name = serializers.CharField(source='auth_user.last_name')
    email = serializers.CharField(source='auth_user.email')

    class Meta:
        model = UserProfile
        fields = ['auth_user_id', 'username', 'email', 'first_name', 'last_name']


class UserProfileSerializer(serializers.ModelSerializer):
    # user = UserSerializer()
    # auth_user_id = serializers.CharField(source='user.id', read_only=True)
    username = serializers.CharField(source='auth_user.username')
    first_name = serializers.CharField(source='auth_user.first_name')
    last_name = serializers.CharField(source='auth_user.last_name')
    email = serializers.CharField(source='auth_user.email')
    piggybanks = serializers.PrimaryKeyRelatedField(queryset=PiggyBank.objects.all(), many=True)

    class Meta:
        model = UserProfile
        fields = ['auth_user_id', 'username', 'email', 'first_name', 'last_name', 'piggybanks']


class ParticipateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='participant.auth_user.username', read_only=True)
    first_name = serializers.CharField(source='participant.auth_user.first_name', read_only=True)
    last_name = serializers.CharField(source='participant.auth_user.last_name', read_only=True)

    class Meta:
        model = Participate
        fields = ['participant', 'username', 'first_name', 'last_name', 'credit']


class PartialParticipateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='participant.auth_user.username', read_only=True)

    class Meta:
        model = Participate
        fields = ['username', 'credit']


class PiggyBankSerializer(serializers.ModelSerializer):
    # participants = PartialParticipateSerializer(source='participate_set', many=True, read_only=True)
    created_by_username = serializers.CharField(source='created_by.auth_user.username', read_only=True)

    class Meta:
        model = PiggyBank
        fields = ['id', 'pb_name', 'pb_description', 'created_by', 'created_by_username', 'closed']  # , 'participants']


class ProductSerializer(serializers.ModelSerializer):
    def validate(self, data):
        """
        Check that pieces >= 1.
        """
        if data.get('pieces') is not None and data.get('pieces') < 1:
            raise serializers.ValidationError({"error": "Check your input."})
        return data

    class Meta:
        model = Product
        fields = ['id', 'name', 'description', 'pieces', 'valid_for_piggybank']


class EntrySerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    entered_by_username = serializers.CharField(source='entered_by.auth_user.username', read_only=True)
    piggybank_name = serializers.CharField(source='piggybank.pb_name', read_only=True)

    def validate(self, data):
        """
        Check that set_quantity >= 1 and entry_price is a non-negative number.
        """
        if data.get('set_quantity') is not None and data.get('set_quantity') < 1 \
                or data.get('entry_price') is not None and data.get('entry_price') < 0:
            raise serializers.ValidationError({"error": "Check your input."})
        return data

    class Meta:
        model = Entry
        fields = ['id', 'product', 'product_name', 'piggybank', 'piggybank_name', 'entry_date',
                  'entry_price', 'entered_by', 'entered_by_username', 'set_quantity']
        extra_kwargs = {'product': {'required': True},
                        'piggybank': {'required': True},
                        'entered_by': {'required': True},
                        'entry_date': {'required': True},
                        'set_quantity': {'required': True}
                        }


class PurchaseSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    purchaser_username = serializers.CharField(source='purchaser.auth_user.username', read_only=True)
    piggybank_name = serializers.CharField(source='piggybank.pb_name', read_only=True)

    def validate(self, data):
        """
        Check that pieces >= 1 and unitary_purchase_price is a non-negative number.
        """
        if data.get('pieces') is not None and data.get('pieces') < 1 \
                or data.get('unitary_purchase_price') is not None and data.get('unitary_purchase_price') < 0:
            raise serializers.ValidationError({"error": "Check your input."})
        return data

    class Meta:
        model = Purchase
        fields = ['id', 'product', 'product_name', 'piggybank', 'piggybank_name', 'purchaser', 'purchaser_username',
                  'purchase_date', 'unitary_purchase_price', 'pieces']
        extra_kwargs = {'product': {'required': True},
                        'piggybank': {'required': True},
                        'purchaser': {'required': True},
                        'purchase_date': {'required': True},
                        'pieces': {'required': True}
                        }


class StockSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    entered_by_username = serializers.CharField(source='entered_by.auth_user.username', read_only=True)

    class Meta:
        model = Stock
        fields = ['product', 'product_name', 'entry_date',
                  'entered_by', 'entered_by_username', 'unitary_price', 'pieces']


class InvitationSerializer(serializers.ModelSerializer):
    invited_username = serializers.CharField(source='invited.auth_user.username', read_only=True)
    inviter_username = serializers.CharField(source='inviter.auth_user.username', read_only=True)
    piggybank_name = serializers.CharField(source='piggybank.pb_name', read_only=True)

    class Meta:
        model = Invitation
        fields = ['id', 'inviter', 'inviter_username', 'invited', 'invited_username', 'invitation_date',
                  'piggybank', 'piggybank_name']
