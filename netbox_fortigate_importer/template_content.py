from netbox.plugins import PluginTemplateExtension


class DeviceFortiGatePanel(PluginTemplateExtension):
    """On a device bound to a FortiGate: its binding and last import."""
    models = ('dcim.device',)

    def right_page(self):
        device = self.context['object']
        binding = device.fortigate_bindings.first()
        if binding is None:
            return ''
        return self.render('netbox_fortigate_importer/inc/device_panel.html', extra_context={
            'binding': binding, 'last_run': binding.last_run,
        })


template_extensions = [DeviceFortiGatePanel]
