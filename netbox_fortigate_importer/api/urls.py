from netbox.api.routers import NetBoxRouter

from . import views

router = NetBoxRouter()
router.APIRootView = views.FortiGateImporterRootView
router.register('fortigates', views.FortiGateBindingViewSet)
router.register('runs', views.ImportRunViewSet)
router.register('changes', views.PlannedChangeViewSet)

urlpatterns = router.urls
