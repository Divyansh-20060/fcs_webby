# Generated by Django 4.2.5 on 2023-10-21 15:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('realestate', '0005_rename_amenitiy_listinginfo_amenity'),
    ]

    operations = [
        migrations.DeleteModel(
            name='ListingInfo',
        ),
    ]