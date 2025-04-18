from django.urls import path
from .views import logout_view
from .views import login_view
from . import views
from django.shortcuts import render
from .views import save_story
urlpatterns = [
    path('', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
   
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path("dashboard", views.dashboard, name="dashboard"),
    path('alumni-directory/', views.alumni_directory_view, name='alumni_directory'),
    path('jobs/statistics', views.jobs_statistics_view, name='jobs_statistics'),
    path('jobs_statistics', views.jobs_statistics, name='jobs_statistics'),
    path('successstory_admin/stories', views.successstory_admin_view, name='successstory_admin'),
    path('survey/', views.survey_view, name='survey'),
    path('feedback/', views.feedback_view, name='feedback'),
    path('newsletter/', views.newsletter_view, name='newsletter'),
    path('upload-alumni/', views.upload_alumni, name='upload_alumni'),
    #path('error/', error_view, name='error_page'),
    path('upload-excel/', views.upload_excel, name='upload_excel'),
 
    path('fetch_alumni/', views.fetch_alumni, name='fetch_alumni'),
    path('fetch_alumni/<str:doc_id>/', views.fetch_alumni_by_id, name='fetch_alumni_by_id'),
    path('edit_alumni/<str:doc_id>/', views.edit_alumni, name='edit_alumni'),
    path('delete_alumni/<str:doc_id>/', views.delete_alumni, name='delete_alumni'),
    
    path('successstory_admin/form.html', lambda request: render(request, 'authentication/form.html')),
    path('form/', views.form_view, name='form'),
    path('save-story/', save_story, name='save_story'),
    path('get-stories/', views.get_stories, name='get_stories'),  # New endpoint to fetch stories
    path('delete-story/<str:story_id>/', views.delete_story, name='delete_story'),
    path('edit-story/<str:story_id>/', views.edit_story, name='edit_story'),
    path('delete-image/<str:story_id>/', views.delete_image_from_story, name='delete_image_from_story'),

    path('survey_form/', views.survey_form_page, name='survey_form_page'),
    path('submit_survey/', views.submit_survey, name='submit_survey'),
    path('get_surveys/', views.get_surveys, name='get_surveys'),
    path('submit_response/', views.submit_response, name='submit_response'),  # Optional
    path('get_responses/<survey_id>/', views.get_responses, name='get_responses'),
    
    path("fetch_feedback/", views.fetch_feedback, name="fetch_feedback"),
   
    path('newsletter_form/', views.newsletter_form_page, name='newsletter_form_page'),
    path('newsletter/delete/<str:newsletter_id>/', views.newsletter_delete, name='newsletter_delete'),
    path('get_newsletter/<str:newsletter_id>/', views.get_newsletter, name='get_newsletter'),
    path('update_newsletter/<str:newsletter_id>/', views.update_newsletter, name='update_newsletter'),

    path('forgot-password/', views.admin_forgot_password, name='admin_forgot_password'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),

    path('requests/', views.admin_requests_view, name='admin_requests'),
    path('requests/accept/<str:request_id>/', views.accept_request_view, name='accept_request'),
    path('requests/reject/<str:request_id>/', views.reject_request_view, name='reject_request'),
    
    
]
