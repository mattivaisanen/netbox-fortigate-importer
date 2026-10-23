from django.urls import include, path

from utilities.urls import get_model_urls

from . import views  # noqa: F401 - registers the model views

APP = 'netbox_fortigate_importer'

urlpatterns = [
    path('fortigates/', include(get_model_urls(APP, 'fortigatebinding', detail=False))),
    path('fortigates/<int:pk>/', include(get_model_urls(APP, 'fortigatebinding'))),
    path('runs/upload/', views.ImportRunUploadView.as_view(), name='importrun_upload'),
    path('runs/', include(get_model_urls(APP, 'importrun', detail=False))),
    path('runs/<int:pk>/', include(get_model_urls(APP, 'importrun'))),
    path('changes/<int:pk>/', include(get_model_urls(APP, 'plannedchange'))),
]
