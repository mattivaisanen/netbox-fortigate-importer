from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_fortigate_importer', '0002_binding_new_device'),
    ]

    operations = [
        migrations.AddField(
            model_name='importrun',
            name='data_sha256',
            field=models.CharField(blank=True, max_length=64, verbose_name='SHA-256 of the configuration'),
        ),
    ]
