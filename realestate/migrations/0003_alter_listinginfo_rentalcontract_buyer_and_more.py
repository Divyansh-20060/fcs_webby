# Generated by Django 4.2.5 on 2023-10-21 12:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('realestate', '0002_alter_listinginfo_rentalcontract_buyer_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='listinginfo',
            name='rentalContract_buyer',
            field=models.FileField(blank=True, null=True, upload_to='Rental_buyer/'),
        ),
        migrations.AlterField(
            model_name='listinginfo',
            name='rentalContract_seller',
            field=models.FileField(blank=True, null=True, upload_to='Rental_seller/'),
        ),
        migrations.AlterField(
            model_name='listinginfo',
            name='saleContract',
            field=models.FileField(blank=True, null=True, upload_to='Sale_Contract/'),
        ),
    ]
