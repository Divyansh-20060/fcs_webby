# Generated by Django 4.2.5 on 2023-10-12 08:47

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='AdminInfo',
            fields=[
                ('name', models.CharField(max_length=50)),
                ('username', models.CharField(max_length=50, primary_key=True, serialize=False)),
                ('password', models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='BuyerInfo',
            fields=[
                ('name', models.CharField(max_length=50)),
                ('username', models.CharField(max_length=50, primary_key=True, serialize=False)),
                ('password', models.CharField(max_length=200)),
                ('public_key', models.FileField(upload_to='public_keys/')),
                ('proof_of_id', models.FileField(upload_to='proofIDs/')),
                ('phone', models.CharField(max_length=10)),
                ('email', models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name='SellerInfo',
            fields=[
                ('name', models.CharField(max_length=50)),
                ('username', models.CharField(max_length=50, primary_key=True, serialize=False)),
                ('password', models.CharField(max_length=200)),
                ('public_key', models.FileField(upload_to='publicKeys/')),
                ('proof_of_id', models.FileField(upload_to='proofIDs/')),
                ('phone', models.CharField(default='strings', max_length=10)),
                ('email', models.CharField(default='strings', max_length=50)),
            ],
        ),
    ]
