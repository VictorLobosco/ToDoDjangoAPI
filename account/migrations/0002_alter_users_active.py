# Generated by Django 4.0.2 on 2022-02-16 19:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='users',
            name='active',
            field=models.BooleanField(default=True),
        ),
    ]
