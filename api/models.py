from django.contrib.auth.models import User as AuthUser
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver


# ----------- MODELS -------------


class PiggyBank(models.Model):
    created_by = models.ForeignKey('UserProfile', models.CASCADE)
    pb_name = models.CharField(max_length=30, default='My Piggybank')
    pb_description = models.CharField(max_length=255, blank=True, null=True)
    closed = models.BooleanField(default=False, null=False)


class Participate(models.Model):
    participant = models.ForeignKey('UserProfile', models.CASCADE)
    piggybank = models.ForeignKey(PiggyBank, models.CASCADE)
    credit = models.DecimalField(max_digits=6, decimal_places=2, default=0)

    class Meta:
        unique_together = (('participant', 'piggybank'),)


# We're not changing the auth method, so we create a table just to store user info
class UserProfile(models.Model):
    auth_user = models.OneToOneField(AuthUser, models.CASCADE, primary_key=True)
    piggybanks = models.ManyToManyField(PiggyBank, through=Participate, blank=True)
    email_confirmed = models.BooleanField(default=False, null=False)
    password_reset = models.BooleanField(default=False, null=False)
    password_reset_date = models.DateTimeField()

    def __str__(self):
        return "User {}, username: \"{}\", email: \"{}\"".format(self.user_id, self.auth_user.username,
                                                                 self.auth_user.email)


class Product(models.Model):
    name = models.CharField(unique=True, max_length=30)
    description = models.TextField(blank=True, null=True)
    # number of pieces that compose the product (1 to N)
    pieces = models.BigIntegerField()


# This model will be the history of the stock for every product and pb
class Stock(models.Model):
    product = models.ForeignKey(Product, models.DO_NOTHING)
    piggybank = models.ForeignKey(PiggyBank, models.DO_NOTHING)
    unitary_price = models.DecimalField(max_digits=6, decimal_places=2)
    pieces = models.BigIntegerField()
    entry_date = models.DateTimeField()
    entered_by = models.ForeignKey('UserProfile', models.CASCADE)

    class Meta:
        unique_together = (('product', 'piggybank', 'entry_date', 'entered_by'),)


class Entry(models.Model):
    product = models.ForeignKey(Product, models.DO_NOTHING)
    piggybank = models.ForeignKey(PiggyBank, models.DO_NOTHING)
    entered_by = models.ForeignKey('UserProfile', models.CASCADE)
    entry_date = models.DateTimeField()
    entry_price = models.DecimalField(max_digits=6, decimal_places=2)
    # set quantity, this is different from pieces!
    set_quantity = models.BigIntegerField(default=1)

    class Meta:
        unique_together = (('product', 'piggybank', 'entry_date', 'entered_by'),)


class Purchase(models.Model):
    product = models.ForeignKey(Product, models.DO_NOTHING)
    piggybank = models.ForeignKey(PiggyBank, models.DO_NOTHING)
    purchaser = models.ForeignKey('UserProfile', models.CASCADE)
    purchase_date = models.DateTimeField()
    unitary_purchase_price = models.DecimalField(max_digits=6, decimal_places=2)
    pieces = models.BigIntegerField()

    class Meta:
        unique_together = (('product', 'piggybank', 'purchase_date', 'purchaser'),)


class Invitation(models.Model):
    inviter = models.ForeignKey('UserProfile', models.CASCADE, related_name='inviters')
    invited = models.ForeignKey('UserProfile', models.CASCADE, related_name='inviteds')
    piggybank = models.ForeignKey(PiggyBank, models.CASCADE)
    invitation_date = models.DateTimeField()

    class Meta:
        unique_together = (('invited', 'piggybank'),)


# ----------------- SIGNALS ---------------

# Automatically update/create UserProfile instance whenever a user is updated/created.
@receiver(post_save, sender=AuthUser)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(auth_user=instance)


@receiver(post_save, sender=AuthUser)
def save_user_profile(sender, instance, **kwargs):
    instance.userprofile.save()


# Whenever a user creates a piggybank, it must be present in participate relation with default credit.
@receiver(post_save, sender=PiggyBank)
def create_participate(sender, instance, created, **kwargs):
    if created:
        Participate.objects.create(participant=instance.created_by, piggybank=instance)


# TODO: find out if this is useless or not.
@receiver(post_save, sender=PiggyBank)
def save_participate(sender, instance, **kwargs):
    for p in instance.participate_set.all():
        p.save()
