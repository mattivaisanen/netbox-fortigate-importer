# The device of a new FortiGate is created by the apply, not when it is chosen.

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dcim", "0250_cooling_infrastructure"),  # oldest supported: NetBox 4.7.0
        ("netbox_fortigate_importer", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="fortigatebinding",
            name="new_device",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AlterField(
            model_name="fortigatebinding",
            name="device",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="fortigate_bindings",
                to="dcim.device",
            ),
        ),
    ]
