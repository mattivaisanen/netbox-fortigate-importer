from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_variables
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework.routers import APIRootView

from netbox.api.authentication import TokenPermissions
from netbox.api.viewsets import NetBoxModelViewSet, NetBoxReadOnlyModelViewSet

from .. import filtersets, jobs, planner, services
from ..jobs import active_job
from ..mappers import MapperError
from ..models import FortiGateBinding, ImportRun, PlannedChange, RunStatusChoices
from ..parser import ParseError
from ..parser.files import ConfigFileError, PasswordRequired
from . import serializers


class FortiGateImporterRootView(APIRootView):
    def get_view_name(self):
        return 'FortiGate importer'


class FortiGateBindingViewSet(NetBoxModelViewSet):
    queryset = FortiGateBinding.objects.select_related('device', 'virtual_chassis', 'asn_rir').prefetch_related('tags')
    serializer_class = serializers.FortiGateBindingSerializer
    filterset_class = filtersets.FortiGateBindingFilterSet


class RunActionPermissions(TokenPermissions):
    """
    POST on an existing run (plan, dry run, apply, rollback) needs only view
    permission on the run here; each action checks its own permission. Without
    this, NetBox would treat the POST as "add" and require add_importrun.
    """
    perms_map = {**TokenPermissions.perms_map, 'POST': ['%(app_label)s.view_%(model_name)s']}


#: Actions on an existing run.
RUN_ACTIONS = ('plan', 'dry_run', 'apply', 'rollback')


class ImportRunViewSet(NetBoxReadOnlyModelViewSet):
    """
    Import runs. POST /upload/ (multipart: file, password, device) reads a
    configuration; then plan, dry-run, apply and rollback act on a run.
    Dry run, apply and rollback are queued as background jobs.
    """
    queryset = ImportRun.objects.select_related('binding').defer('data')
    serializer_class = serializers.ImportRunSerializer
    filterset_class = filtersets.ImportRunFilterSet

    def _require(self, request, perm):
        if not request.user.has_perm(f'netbox_fortigate_importer.{perm}'):
            raise PermissionDenied()

    def initial(self, request, *args, **kwargs):
        # Uploads stay in memory. This must happen before authentication:
        # session authentication checks the CSRF token, which reads the body.
        if self.action == 'upload':
            from ..views import InMemoryUploadHandler

            request._request.upload_handlers = [InMemoryUploadHandler(request._request)]
        super().initial(request, *args, **kwargs)
        if self.action in RUN_ACTIONS and request.user.is_authenticated:
            self.queryset = type(self).queryset.restrict(request.user, 'view')

    @method_decorator(csrf_exempt)
    @action(detail=False, methods=['post'], parser_classes=[MultiPartParser])
    @method_decorator(sensitive_variables())
    def upload(self, request):
        # Keep the password out of Django's error reports.
        request._request.sensitive_post_parameters = ('password',)
        self._require(request, 'add_importrun')
        form = serializers.UploadSerializer(data=request.data)
        form.is_valid(raise_exception=True)
        upload = form.validated_data['file']
        try:
            run = services.ingest(upload.read(), upload.name, request.user,
                                  form.validated_data.get('password') or None)
        except PasswordRequired:
            return Response({'detail': 'This backup is encrypted: send its password.', 'password_required': True},
                            status=status.HTTP_400_BAD_REQUEST)
        except (ConfigFileError, ParseError) as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        finally:
            upload.close()
        if run.binding_id is None and form.validated_data.get('device'):
            from dcim.models import Device

            self._require(request, 'add_fortigatebinding')
            services.bind(run, get_object_or_404(Device.objects.restrict(request.user, 'view'),
                                                 pk=form.validated_data['device']))
        if run.binding_id is not None:
            services.refresh_binding(run.binding, run.info)
            self._plan(run)
        run.refresh_from_db()
        return Response(self.get_serializer(run).data, status=status.HTTP_201_CREATED)

    @staticmethod
    def _plan(run):
        try:
            planner.plan(run)
        except (planner.PlanError, MapperError) as exc:
            raise ValidationError({'detail': str(exc)})

    @action(detail=True, methods=['post'], permission_classes=[RunActionPermissions])
    def plan(self, request, pk):
        self._require(request, 'change_importrun')
        run = self.get_object()
        self._plan(run)
        run.refresh_from_db()
        return Response(self.get_serializer(run).data)

    def _job(self, request, name, perm, allowed):
        self._require(request, perm)
        run = self.get_object()
        if active_job(run):
            raise ValidationError({'detail': 'This run already has a job queued or running.'})
        if not allowed(run):
            raise ValidationError({'detail': f'Not possible while the run is "{run.get_status_display()}".'})
        try:
            job = jobs.enqueue(run, request.user, name)
        except jobs.QueueError as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response({'job': job.pk, 'job_url': job.get_absolute_url()}, status=status.HTTP_202_ACCEPTED)

    @action(detail=True, methods=['post'], url_path='dry-run', permission_classes=[RunActionPermissions])
    def dry_run(self, request, pk):
        return self._job(request, 'dry-run', 'apply_importrun', lambda run: run.can_apply)

    @action(detail=True, methods=['post'], permission_classes=[RunActionPermissions])
    def apply(self, request, pk):
        return self._job(request, 'apply', 'apply_importrun', lambda run: run.can_apply)

    @action(detail=True, methods=['post'], permission_classes=[RunActionPermissions])
    def rollback(self, request, pk):
        return self._job(request, 'rollback', 'rollback_importrun', lambda run: run.can_rollback)


class PlannedChangeViewSet(NetBoxReadOnlyModelViewSet):
    """Planned changes. PATCH {"decision": ...} sets a decision while the run is ready for review."""
    queryset = PlannedChange.objects.select_related('object_type', 'run')
    serializer_class = serializers.PlannedChangeSerializer
    filterset_class = filtersets.PlannedChangeFilterSet

    def partial_update(self, request, pk=None):
        if not request.user.has_perm('netbox_fortigate_importer.change_plannedchange'):
            raise PermissionDenied()
        change = self.get_object()
        serializer = self.get_serializer(change, data={'decision': request.data.get('decision')}, partial=True)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            # Waits for an apply that holds the run, then sees its job.
            run = ImportRun.objects.select_for_update().get(pk=change.run_id)
            if run.status != RunStatusChoices.PLANNED or jobs.busy(run):
                raise ValidationError({'decision': 'The run is not ready for review.'})
            change.decision = serializer.validated_data['decision']
            change.decided_by = request.user
            change.full_clean()
            change.save(update_fields=['decision', 'decided_by'])
            ImportRun.objects.filter(pk=change.run_id).update(dry_run={})
        return Response(self.get_serializer(change).data)
