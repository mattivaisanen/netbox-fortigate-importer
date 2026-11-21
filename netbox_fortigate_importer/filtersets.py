import django_filters
from django.db.models import Q
from django.utils.translation import gettext as _

from dcim.models import Device
from netbox.filtersets import BaseFilterSet, NetBoxModelFilterSet

from .models import (
    ActionChoices,
    DecisionChoices,
    FortiGateBinding,
    ImportRun,
    OutcomeChoices,
    PlannedChange,
    RunStatusChoices,
)


class FortiGateBindingFilterSet(NetBoxModelFilterSet):
    device_id = django_filters.ModelMultipleChoiceFilter(queryset=Device.objects.all(), label=_('Device (ID)'))

    class Meta:
        model = FortiGateBinding
        fields = ('id', 'name', 'serial', 'hostname', 'model_code', 'firmware', 'multi_vdom', 'description')

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(name__icontains=value) | Q(serial__icontains=value) | Q(hostname__icontains=value)
            | Q(device__name__icontains=value) | Q(description__icontains=value)
        )


class ImportRunFilterSet(BaseFilterSet):
    q = django_filters.CharFilter(method='search', label=_('Search'))
    status = django_filters.MultipleChoiceFilter(choices=RunStatusChoices)
    binding_id = django_filters.ModelMultipleChoiceFilter(
        queryset=FortiGateBinding.objects.all(), label=_('FortiGate (ID)'),
    )

    class Meta:
        model = ImportRun
        fields = ('id', 'filename', 'encrypted')

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(
            Q(filename__icontains=value) | Q(binding__name__icontains=value) | Q(info__hostname__icontains=value)
        )


class PlannedChangeFilterSet(BaseFilterSet):
    q = django_filters.CharFilter(method='search', label=_('Search'))
    action = django_filters.MultipleChoiceFilter(choices=ActionChoices)
    decision = django_filters.MultipleChoiceFilter(choices=DecisionChoices)
    outcome = django_filters.MultipleChoiceFilter(choices=OutcomeChoices)
    section = django_filters.MultipleChoiceFilter(
        choices=lambda: [(s, s) for s in PlannedChange.objects.values_list('section', flat=True).distinct()],
    )
    vdom = django_filters.CharFilter()
    run_id = django_filters.ModelMultipleChoiceFilter(queryset=ImportRun.objects.all())
    changed = django_filters.BooleanFilter(method='filter_changed', label=_('Hide unchanged'))
    dry_run = django_filters.MultipleChoiceFilter(
        choices=OutcomeChoices, method='filter_dry_run', label=_('Last dry run result'),
    )

    class Meta:
        model = PlannedChange
        fields = ('id', 'key')

    def search(self, queryset, name, value):
        if not value.strip():
            return queryset
        return queryset.filter(Q(label__icontains=value) | Q(key__icontains=value) | Q(note__icontains=value))

    def filter_changed(self, queryset, name, value):
        return queryset.exclude(action=ActionChoices.NOOP) if value else queryset

    def filter_dry_run(self, queryset, name, value):
        """Changes by their result in their run's last dry run (kept on the run, not the change)."""
        if not value:
            return queryset
        wanted = Q(pk__in=[])
        runs = ImportRun.objects.filter(pk__in=queryset.values('run_id')).only('pk', 'dry_run')
        for run in runs:
            items = (run.dry_run or {}).get('items', {})
            keys = [key for key, item in items.items() if item.get('outcome') in value]
            wanted |= Q(run_id=run.pk, key__in=keys)
        return queryset.filter(wanted)
