# Generated by Django 4.0.5 on 2022-07-21 02:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('invoicesystem', '0006_invoice_invoicedetails'),
    ]

    operations = [
        migrations.AddField(
            model_name='invoice',
            name='total_amount',
            field=models.DecimalField(decimal_places=2, max_digits=9, null=True),
        ),
    ]
