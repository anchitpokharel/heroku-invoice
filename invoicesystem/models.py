import email
from email.policy import default
from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class User(AbstractUser):
    company_name = models.CharField(max_length=255)
    email = models.EmailField(max_length=127, unique=True)
    is_verified = models.BooleanField(default=False)

    username = None

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.first_name + " " + self.last_name


class Company(models.Model):
    company_name = models.CharField(max_length=255)
    address = models.CharField(max_length=127)
    email = models.EmailField(max_length=127)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return self.company_name


class Currency(models.Model):
    currency = models.CharField(max_length=127)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.currency


class Language(models.Model):
    language = models.CharField(max_length=127)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.language


class Client(models.Model):
    full_name = models.CharField(max_length=127)
    email = models.EmailField(max_length=127, unique=True)
    phone_number = models.CharField(max_length=50)
    address = models.CharField(max_length=127)
    currency = models.ForeignKey(Currency, on_delete=models.SET_NULL, null=True)
    language = models.ForeignKey(Language, on_delete=models.SET_NULL, null=True)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.full_name


class Invoice(models.Model):
    client = models.ForeignKey(Client, on_delete=models.SET_NULL, null=True)
    due_date = models.DateField()
    currency = models.ForeignKey(Currency, on_delete=models.SET_NULL, null=True)
    language = models.ForeignKey(Language, on_delete=models.SET_NULL, null=True)
    notes = models.CharField(max_length=255)
    discount = models.DecimalField(max_digits=5, decimal_places=2, null=True)
    tax = models.DecimalField(max_digits=5, decimal_places=2, null=True)
    total_amount = models.DecimalField(max_digits=9, decimal_places=2, default=0.00)

    def __str__(self):
        return str(self.id)


class InvoiceDetails(models.Model):
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE)
    description = models.CharField(max_length=255, null=False)
    usd = models.DecimalField(max_digits=9, decimal_places=2)
    quantity = models.IntegerField()

    def __str__(self):
        return str(self.invoice)
