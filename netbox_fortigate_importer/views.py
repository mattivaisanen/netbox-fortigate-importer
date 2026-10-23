from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.files.uploadhandler import MemoryFileUploadHandler, StopUpload
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import NoReverseMatch, reverse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.generic import View

from netbox.object_actions import AddObject, BulkDelete, BulkExport, DeleteObject, EditObject
from netbox.views import generic
from utilities.forms import restrict_form_fields
from utilities.request import safe_for_redirect
from utilities.views import ConditionalLoginRequiredMixin, register_model_view

from . import dependencies, filtersets, forms, planner, services, tables
from . import jobs
from .jobs import active_job
from .mappers import MapperError
from .models import (
    ActionChoices, DecisionChoices, FortiGateBinding, ImportRun, PlannedChange, RunStatusChoices,
)
from .parser import ParseError
from .parser.files import ConfigFileError, PasswordRequired, UnsupportedEncryption
from .settings import get_setting


#
# FortiGates (bindings)
#

@register_model_view(FortiGateBinding, 'list', path='', detail=False)
class FortiGateBindingListView(generic.ObjectListView):
    queryset = FortiGateBinding.objects.select_related('device', 'virtual_chassis')
    table = tables.FortiGateBindingTable
    filterset = filtersets.FortiGateBindingFilterSet
    filterset_form = forms.FortiGateBindingFilterForm
    actions = (AddObject, BulkExport, BulkDelete)


@register_model_view(FortiGateBinding)
class FortiGateBindingView(generic.ObjectView):
    queryset = FortiGateBinding.objects.select_related('device', 'virtual_chassis', 'asn_rir')
    actions = (EditObject, DeleteObject)

    def get_extra_context(self, request, instance):
        runs = tables.ImportRunTable(instance.runs.select_related('created_by', 'applied_by').defer('data')[:20])
        runs.configure(request)
        managed = instance.managed_objects.values('object_type__app_label', 'object_type__model')
        counts = {}
        for row in managed:
            label = f'{row["object_type__app_label"]}.{row["object_type__model"]}'
            counts[label] = counts.get(label, 0) + 1
        return {
            'runs_table': runs,
            'managed_counts': sorted(counts.items()),
            'managed_total': sum(counts.values()),
            'options': planner.run_options(instance),
        }


@register_model_view(FortiGateBinding, 'add', detail=False)
@register_model_view(FortiGateBinding, 'edit')
class FortiGateBindingEditView(generic.ObjectEditView):
    queryset = FortiGateBinding.objects.all()
    form = forms.FortiGateBindingForm


@register_model_view(FortiGateBinding, 'delete')
class FortiGateBindingDeleteView(generic.ObjectDeleteView):
    queryset = FortiGateBinding.objects.all()


@register_model_view(FortiGateBinding, 'bulk_delete', path='delete', detail=False)
class FortiGateBindingBulkDeleteView(generic.BulkDeleteView):
    queryset = FortiGateBinding.objects.all()
    filterset = filtersets.FortiGateBindingFilterSet
    table = tables.FortiGateBindingTable


#
# Upload
#

class InMemoryUploadHandler(MemoryFileUploadHandler):
    """
    Keeps every upload in memory, whatever its size, up to the plugin's
    max_upload_mb. Django would otherwise write big uploads to a temporary
    file, and the configuration must never touch the disk.
    """

    def handle_raw_input(self, input_data, META, content_length, boundary, encoding=None):
        limit = int(get_setting('max_upload_mb') or 50) * 1024 * 1024
        if content_length and content_length > limit:
            raise StopUpload(connection_reset=True)
        self.activated = True

    def receive_data_chunk(self, raw_data, start):
        limit = int(get_setting('max_upload_mb') or 50) * 1024 * 1024
        if start + len(raw_data) > limit:
            raise StopUpload(connection_reset=True)
        return super().receive_data_chunk(raw_data, start)


def _wants_json(request):
    return request.headers.get('x-requested-with') == 'fetch' or 'application/json' in request.headers.get('accept', '')


@method_decorator(csrf_exempt, name='dispatch')
class ImportRunUploadView(ConditionalLoginRequiredMixin, View):
    """
    Drag & drop or choose a file. The page posts it with fetch(); when the
    file turns out to be an encrypted backup, the page asks for the password
    and posts the same file again with it. Nothing is kept between the two.
    """
    template_name = 'netbox_fortigate_importer/upload.html'

    def get(self, request):
        if not request.user.has_perm('netbox_fortigate_importer.add_importrun'):
            raise PermissionDenied
        return render(request, self.template_name, {
            'form': forms.UploadForm(), 'max_upload_mb': get_setting('max_upload_mb'),
        })

    @method_decorator(sensitive_post_parameters('password'))
    def post(self, request):
        # Replace the upload handlers before anything reads the body (CSRF
        # included, hence csrf_exempt here and csrf_protect inside).
        request.upload_handlers = [InMemoryUploadHandler(request)]
        return csrf_protect(self._post)(request)

    @method_decorator(sensitive_variables())
    def _post(self, request):
        if not request.user.has_perm('netbox_fortigate_importer.add_importrun'):
            raise PermissionDenied
        form = forms.UploadForm(request.POST, request.FILES)
        error, password_required = None, False
        if form.is_valid():
            upload = form.cleaned_data['file']
            password = form.cleaned_data.get('password') or None
            try:
                run = services.ingest(upload.read(), upload.name, request.user, password)
            except PasswordRequired:
                password_required = True
                if not password:
                    error = _('This is an encrypted backup. Enter the password it was saved with.')
            except UnsupportedEncryption as exc:
                # Another password won't help: don't ask for one again.
                error = str(exc)
            except (ConfigFileError, ParseError) as exc:
                error = str(exc)
                password_required = bool(password)
            else:
                url = self._next(request, run)
                if _wants_json(request):
                    return JsonResponse({'redirect': url})
                return redirect(url)
            finally:
                upload.close()
        else:
            error = '; '.join(' '.join(v) for v in form.errors.values())
        if _wants_json(request):
            return JsonResponse({'error': error, 'password_required': password_required}, status=400)
        return render(request, self.template_name, {
            'form': forms.UploadForm(), 'error': error, 'password_required': password_required,
            'max_upload_mb': get_setting('max_upload_mb'),
        }, status=400)

    @staticmethod
    def _next(request, run):
        if run.binding_id is None:
            return reverse('plugins:netbox_fortigate_importer:importrun_bind', args=[run.pk])
        services.refresh_binding(run.binding, run.info)
        try:
            planner.plan(run)
        except (planner.PlanError, MapperError) as exc:
            messages.error(request, str(exc))
        return run.get_absolute_url()


#
# Import runs
#

@register_model_view(ImportRun, 'list', path='', detail=False)
class ImportRunListView(generic.ObjectListView):
    queryset = ImportRun.objects.select_related('binding', 'created_by', 'applied_by').defer('data')
    table = tables.ImportRunTable
    filterset = filtersets.ImportRunFilterSet
    filterset_form = forms.ImportRunFilterForm
    actions = (BulkExport, BulkDelete)


@register_model_view(ImportRun)
class ImportRunView(generic.ObjectView):
    queryset = ImportRun.objects.select_related('binding', 'binding__device', 'created_by', 'applied_by')
    template_name = 'netbox_fortigate_importer/importrun.html'
    actions = (DeleteObject,)

    def get_extra_context(self, request, instance):
        changes = instance.changes.select_related('object_type').prefetch_related('object')
        filterset = filtersets.PlannedChangeFilterSet(request.GET, queryset=changes)
        queryset = filterset.qs if filterset.is_valid() else changes
        if 'changed' not in request.GET:
            queryset = queryset.exclude(action=ActionChoices.NOOP)
        job = active_job(instance)
        can_decide = instance.status == RunStatusChoices.PLANNED and \
            request.user.has_perm('netbox_fortigate_importer.change_plannedchange')
        table = tables.PlannedChangeTable(queryset, dry_run=instance.dry_run)
        if can_decide:
            # Checkboxes, so single changes can be approved or skipped.
            table.columns.show('pk')
        table.configure(request)
        if not (instance.dry_run or {}).get('items'):
            table.columns.hide('dry_run')
        summary = instance.summary or {}
        return {
            'changes_table': table,
            'summary': summary,
            'action_counts': [(value, label, color, summary.get('actions', {}).get(value, 0))
                              for value, label, color in ActionChoices.CHOICES],
            'active_job': job,
            'no_worker': NO_WORKER if job and job.status == 'pending' and jobs.workers_running() is False else '',
            'can_apply': instance.can_apply and request.user.has_perm('netbox_fortigate_importer.apply_importrun'),
            'can_rollback': instance.can_rollback and
            request.user.has_perm('netbox_fortigate_importer.rollback_importrun'),
            'can_decide': can_decide,
            'sections': sorted({c for c in instance.changes.values_list('section', flat=True)}),
            'dry_run': instance.dry_run or {},
        }


@register_model_view(ImportRun, 'delete')
class ImportRunDeleteView(generic.ObjectDeleteView):
    queryset = ImportRun.objects.all()


@register_model_view(ImportRun, 'bulk_delete', path='delete', detail=False)
class ImportRunBulkDeleteView(generic.BulkDeleteView):
    queryset = ImportRun.objects.all()
    filterset = filtersets.ImportRunFilterSet
    table = tables.ImportRunTable


class _RunActionView(ConditionalLoginRequiredMixin, View):
    permission = None

    def get_run(self, request, pk):
        run = get_object_or_404(ImportRun.objects.restrict(request.user, 'view'), pk=pk)
        if self.permission and not request.user.has_perm(self.permission):
            raise PermissionDenied
        return run


@register_model_view(ImportRun, 'bind')
class ImportRunBindView(_RunActionView):
    """Choose the NetBox device a configuration belongs to."""
    permission = 'netbox_fortigate_importer.add_fortigatebinding'
    template_name = 'netbox_fortigate_importer/importrun_bind.html'

    def get(self, request, pk):
        run = self.get_run(request, pk)
        candidates = services.candidate_devices(run.info, request.user)
        initial = {'name': run.info.get('hostname')}
        if candidates:
            initial['device'] = candidates[0]
        return self.render(request, run, self.form(request, initial=initial), candidates)

    @staticmethod
    def form(request, *args, **kwargs):
        """The form, offering only devices, sites, ... the user may see."""
        form = forms.BindForm(*args, **kwargs)
        restrict_form_fields(form, request.user)
        return form

    def post(self, request, pk):
        run = self.get_run(request, pk)
        form = self.form(request, request.POST)
        if not form.is_valid():
            return self.render(request, run, form, services.candidate_devices(run.info, request.user))
        data = form.cleaned_data
        try:
            with transaction.atomic():
                if data['mode'] == form.MODE_EXISTING:
                    services.bind(run, data['device'])
                else:
                    services.bind_new_device(run, data['site'], data['role'], data.get('device_type'),
                                             data.get('name'))
        except Exception as exc:  # noqa: BLE001 - shown on the form
            form.add_error(None, str(getattr(exc, 'messages', [exc])[0]))
            return self.render(request, run, form, services.candidate_devices(run.info, request.user))
        try:
            planner.plan(run)
        except (planner.PlanError, MapperError) as exc:
            messages.error(request, str(exc))
        return redirect(run.get_absolute_url())

    def render(self, request, run, form, candidates):
        return render(request, self.template_name, {'object': run, 'form': form, 'candidates': candidates})


@register_model_view(ImportRun, 'plan')
class ImportRunPlanView(_RunActionView):
    permission = 'netbox_fortigate_importer.change_importrun'

    def post(self, request, pk):
        run = self.get_run(request, pk)
        try:
            planner.plan(run)
            messages.success(request, _('Plan rebuilt against the current NetBox data.'))
        except (planner.PlanError, MapperError) as exc:
            messages.error(request, str(exc))
        return redirect(run.get_absolute_url())


@register_model_view(ImportRun, 'job_status', path='job-status')
class ImportRunJobStatusView(_RunActionView):
    """Whether a job of the run is still queued or running: the run page polls it."""

    def get(self, request, pk):
        run = self.get_run(request, pk)
        job = active_job(run)
        return JsonResponse({
            'active': job is not None,
            'status': job.status if job else None,
            'run_status': run.status,
        })


NO_WORKER = _(
    'No NetBox background worker is running, so the job waits in the queue. Start it '
    '(for netbox-docker: docker compose up -d netbox-worker) and the job runs.'
)


class _JobView(_RunActionView):
    action = None
    message = ''

    def allowed(self, run):
        return run.can_apply

    def post(self, request, pk):
        run = self.get_run(request, pk)
        if active_job(run):
            messages.warning(request, _('This run already has a job queued or running.'))
        elif not self.allowed(run):
            messages.error(request, _('Not possible while the run is "{status}".').format(
                status=run.get_status_display()))
        else:
            try:
                jobs.enqueue(run, request.user, self.action)
            except jobs.QueueError as exc:
                messages.error(request, str(exc))
            else:
                messages.info(request, self.message)
                if jobs.workers_running() is False:
                    messages.warning(request, NO_WORKER)
        return redirect(run.get_absolute_url())


@register_model_view(ImportRun, 'dryrun', path='dry-run')
class ImportRunDryRunView(_JobView):
    permission = 'netbox_fortigate_importer.apply_importrun'
    action = 'dry-run'
    message = _('Dry run queued. Nothing will be saved.')


@register_model_view(ImportRun, 'apply')
class ImportRunApplyView(_JobView):
    permission = 'netbox_fortigate_importer.apply_importrun'
    action = 'apply'
    message = _('Apply queued.')


@register_model_view(ImportRun, 'rollback')
class ImportRunRollbackView(_JobView):
    permission = 'netbox_fortigate_importer.rollback_importrun'
    action = 'rollback'
    message = _('Rollback queued.')

    def allowed(self, run):
        return run.can_rollback


@register_model_view(ImportRun, 'discard')
class ImportRunDiscardView(_RunActionView):
    permission = 'netbox_fortigate_importer.change_importrun'

    def post(self, request, pk):
        run = self.get_run(request, pk)
        if jobs.busy(run):
            messages.error(request, _('This run has a job queued or running.'))
        elif run.status in (RunStatusChoices.PARSED, RunStatusChoices.PLANNED):
            run.status = RunStatusChoices.DISCARDED
            run.save(update_fields=['status'])
            messages.info(request, _('Run discarded. Nothing was written to NetBox.'))
        return redirect(run.get_absolute_url())


@register_model_view(ImportRun, 'decide')
class ImportRunDecideView(_RunActionView):
    """Set the decision of selected (or all filtered) planned changes."""
    permission = 'netbox_fortigate_importer.change_plannedchange'

    def post(self, request, pk):
        run = self.get_run(request, pk)
        if run.status != RunStatusChoices.PLANNED or jobs.busy(run):
            messages.error(request, _('Decisions can only change while the run is ready for review '
                                      'and no job of it is queued or running.'))
            return redirect(run.get_absolute_url())
        decision = request.POST.get('decision')
        labels = {value: label for value, label, *_ in DecisionChoices.CHOICES}
        if decision not in labels:
            messages.error(request, _('Unknown decision.'))
            return redirect(run.get_absolute_url())
        changes = run.changes.exclude(action=ActionChoices.NOOP)
        if request.POST.get('scope') == 'filtered':
            # The list's filters come back prefixed, apart from the form's own fields.
            from django.http import QueryDict

            query = QueryDict(mutable=True)
            for key in request.POST:
                if key.startswith('f_'):
                    query.setlist(key[2:], request.POST.getlist(key))
            changes = filtersets.PlannedChangeFilterSet(query, queryset=changes).qs
        else:
            changes = changes.filter(pk__in=request.POST.getlist('pk'))
        if decision == DecisionChoices.KEEP_NETBOX:
            changes = changes.filter(action=ActionChoices.CONFLICT)
        return_url = request.POST.get('return_url')
        if not return_url or not safe_for_redirect(return_url):
            return_url = run.get_absolute_url()
        selected = list(changes.values_list('pk', flat=True))
        if decision == DecisionChoices.APPROVED:
            # Approving a change whose prerequisites stay unapproved would
            # only get it skipped at apply time: ask first.
            missing = dependencies.missing_for(run, selected)
            choice = request.POST.get('dependencies')
            if missing and choice not in ('include', 'only'):
                return render(request, 'netbox_fortigate_importer/importrun_dependencies.html', {
                    'object': run, 'selected': run.changes.filter(pk__in=selected), 'missing': missing,
                    'selected_pks': selected, 'return_url': return_url,
                })
            if missing and choice == 'include':
                selected += [row.pk for row in missing]
                changes = run.changes.filter(pk__in=selected)
        with transaction.atomic():
            # Waits for an apply that holds the run, then sees its job.
            locked = ImportRun.objects.select_for_update().get(pk=run.pk)
            if locked.status != RunStatusChoices.PLANNED or jobs.busy(locked):
                messages.error(request, _('The run changed meanwhile; nothing was decided.'))
                return redirect(run.get_absolute_url())
            count = changes.update(decision=decision, decided_by=request.user)
            if count:
                # The last dry run was for other decisions.
                ImportRun.objects.filter(pk=run.pk).update(dry_run={})
        messages.success(request, _('{count} changes set to "{decision}".').format(
            count=count, decision=labels[decision]))
        if decision in (DecisionChoices.SKIPPED, DecisionChoices.PENDING):
            affected = dependencies.dependents_of(run, selected)
            if affected:
                names = ', '.join(row.label for row in affected[:5]) + (' …' if len(affected) > 5 else '')
                messages.warning(request, _(
                    '{count} approved changes need these and will be skipped too unless you approve them '
                    'again: {names}').format(count=len(affected), names=names))
        return redirect(return_url)


#
# Planned changes
#

@register_model_view(PlannedChange)
class PlannedChangeView(generic.ObjectView):
    queryset = PlannedChange.objects.select_related('run', 'run__binding', 'object_type', 'decided_by')
    template_name = 'netbox_fortigate_importer/plannedchange.html'
    actions = ()

    def get_extra_context(self, request, instance):
        return {
            'can_decide': instance.run.status == RunStatusChoices.PLANNED and instance.writes and
            request.user.has_perm('netbox_fortigate_importer.change_plannedchange'),
            'decisions': [(v, l) for v, l, *_ in DecisionChoices.CHOICES
                          if v != DecisionChoices.KEEP_NETBOX or instance.action == ActionChoices.CONFLICT],
            'dry_run': (instance.run.dry_run or {}).get('items', {}).get(instance.key),
            'needs': self.needs(instance),
            'change_request_url': change_request_url(instance.change_request_id),
        }

    @staticmethod
    def needs(instance):
        keys = instance.depends_on or []
        rows = {row.key: row for row in instance.run.changes.filter(key__in=keys)}
        return [(key, rows.get(key)) for key in keys]


def change_request_url(pk):
    if not pk:
        return None
    try:
        return reverse('plugins:netbox_change_approval:changerequest', args=[pk])
    except NoReverseMatch:
        return None

