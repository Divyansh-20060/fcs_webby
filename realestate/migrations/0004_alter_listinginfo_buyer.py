# Generated by Django 4.2.5 on 2023-10-21 12:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('realestate', '0003_alter_listinginfo_rentalcontract_buyer_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='listinginfo',
            name='buyer',
            field=models.CharField(max_length=50, null=True),
        ),
    ]