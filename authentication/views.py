from django.shortcuts import render, redirect
from django.contrib import messages
from django import forms
from firebase.firebase import admin_portal_db
from django.core.mail import send_mail
from django.contrib import messages

# Define Login Form
class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control'}))

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib import messages
from firebase.firebase import admin_portal_db  # Adjust to your Firebase setup
from django.views.decorators.csrf import csrf_exempt

def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            # Fetch admin data from Firebase
            admins = admin_portal_db.collection('admins').where('email', '==', email).stream()
            admin_user = None
            for admin in admins:
                admin_data = admin.to_dict()
                if admin_data.get('password') == password:
                    admin_user = admin_data
                    break

            if admin_user:
                request.session['is_authenticated'] = True
                request.session['email'] = email
                request.session['user_name'] = admin_user.get('name', 'Admin')
                messages.success(request, f"Welcome, {admin_user.get('name')}!")
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid email or password.')
        except Exception as e:
            messages.error(request, f"An error occurred: {e}")

    return render(request, 'authentication/login.html')



from django.utils.timezone import now

from .models import AdminOTP
import random
import re


# Admin Forgot Password view
def admin_forgot_password(request):
    """Handles admin password reset requests."""
    if request.method == 'POST':
        email = request.POST.get('email').strip().lower()  # Normalize email
        
        try:
            print(f"Checking for admin user with email: {email}")

            # Check if user exists in Firestore admin_users collection
            admin_ref = firestore.client().collection('admins').where('email', '==', email).stream()
            admin_exists = any(admin_ref)

            if not admin_exists:
                return render(request, 'admin_forgot_password.html', {'error': 'No admin found with this email.'})
            
            # Generate and store OTP
            otp = random.randint(100000, 999999)
            AdminOTP.objects.update_or_create(email=email, defaults={'otp': otp, 'created_at': now()})

            # Send OTP via email
            send_otp_email(email, otp)
            return render(request, 'verify_otp.html', {'email': email})
        
        except Exception as e:
            print(f"Error during forgot password: {e}")
            return render(request, 'admin_forgot_password.html', {'error': 'Unexpected error occurred. Please try again.'})

    return render(request, 'admin_forgot_password.html')


def verify_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        entered_otp = request.POST.get('otp1') + request.POST.get('otp2') + request.POST.get('otp3') + request.POST.get('otp4') + request.POST.get('otp5') + request.POST.get('otp6')

        # Check if entered_otp is empty or None
        if not entered_otp:
            return render(request, 'verify_otp.html', {'error': 'OTP cannot be empty', 'email': email})

        try:
            otp_entry = AdminOTP.objects.get(email=email)

            # Check OTP expiration
            if otp_entry.is_expired():
                otp_entry.delete()
                return render(request, 'admin_forgot_password.html', {'error': 'OTP expired. Request a new one.'})

            # Verify OTP
            if otp_entry.otp == int(entered_otp):  # Ensure OTP is valid (and convert safely to integer)
                return render(request, 'reset_password.html', {'email': email})
            else:
                return render(request, 'verify_otp.html', {'error': 'Invalid OTP', 'email': email})

        except AdminOTP.DoesNotExist:
            return render(request, 'admin_forgot_password.html', {'error': 'No OTP found. Please request a new one.'})

        except ValueError:
            # Handle case where entered OTP is not a valid integer
            return render(request, 'verify_otp.html', {'error': 'Invalid OTP format. Please enter a valid number.', 'email': email})

def send_otp_email(email, otp):
    send_mail(
        'Password Reset OTP',
        f'Your OTP for resetting your admin password is: {otp}. It is valid for 10 minutes.',
        'periyaruniversity08@gmail.com',  # Your sender email
        [email],
        fail_silently=False,
    )





def reset_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        new_password = request.POST.get('password')

        # Validate password
        password_error = validate_password(new_password)
        if password_error:
            return render(request, 'reset_password.html', {'error': password_error, 'email': email})

        try:
            # Step 1: Update Firestore password
            db = firestore.client()
            admin_ref = db.collection('admins').where('email', '==', email).stream()
            
            # Find the admin document
            admin_data = None
            for doc in admin_ref:
                admin_data = doc.to_dict()

            if admin_data:
                # Update the password in Firestore
                admin_ref = db.collection('admins').document(doc.id)
                admin_ref.update({'password': new_password})

                # Step 2: Clear OTP from the AdminOTP table
                AdminOTP.objects.filter(email=email).delete()

                return redirect('login')  # Redirect to login page
            else:
                return render(request, 'reset_password.html', {'error': 'Admin user not found', 'email': email})

        except Exception as e:
            return render(request, 'reset_password.html', {'error': f'Error: {e}', 'email': email})
def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r'[A-Z]', password):
        return "Password must contain an uppercase letter."
    if not re.search(r'[a-z]', password):
        return "Password must contain a lowercase letter."
    if not re.search(r'[0-9]', password):
        return "Password must contain a digit."
    if not re.search(r'[!@#$%^&*]', password):
        return "Password must contain a special character."
    return None




from django.shortcuts import redirect
from django.contrib import messages

def logout_view(request):
    if request.method == 'POST':
        # Clear session data
        request.session.flush()
        messages.success(request, 'You have been logged out.')
        return redirect('login')


def dashboard_view(request):
    # Fetch the logged-in user's name from the session
    user_name = request.session.get('user_name', 'Admin')
    return render(request, 'authentication/dashboard.html', {'name': user_name})

from django.shortcuts import render
from firebase_admin import firestore
from collections import defaultdict
import json

def dashboard(request):
    # Fetch verified users from 'alumni' collection
    alumni_docs = admin_portal_db.collection("alumni").stream()
    
    verified_alumni = 0
    verified_students = 0
    department_counts = defaultdict(int)  # Dictionary to store department-wise counts
    graduation_years = defaultdict(int)  # Dictionary to store count of students per graduation year
    all_years = set()

    for doc in alumni_docs:
        data = doc.to_dict()
        if data.get("status") == "Alumni":
            verified_alumni += 1
        elif data.get("status") == "Student":
            verified_students += 1

        # Count students per department
        department = data.get("department", "Unknown")
        department_counts[department] += 1  

        # Graduation Year Processing
        grad_year = data.get("graduationYear")
        if grad_year:
            graduation_years[int(grad_year)] += 1  # Convert to int to ensure sorting works
            all_years.add(int(grad_year))

    # Ensure all years from min to max exist in the dataset
    if all_years:
        min_year = min(all_years)
        max_year = max(all_years)
        for year in range(min_year, max_year + 1):
            if year not in graduation_years:
                graduation_years[year] = 0

    # **Sort years properly**
    sorted_graduation_years = sorted(graduation_years.keys())
    sorted_graduation_values = [graduation_years[year] for year in sorted_graduation_years]

    # Fetch not verified users from 'requests' collection
    request_docs = admin_portal_db.collection("requests").stream()

    not_verified_alumni = 0
    not_verified_students = 0

    for doc in request_docs:
        data = doc.to_dict()
        if data.get("status") == "Alumni":
            not_verified_alumni += 1
        elif data.get("status") == "Student":
            not_verified_students += 1

    # Convert department counts for frontend
    departments = list(department_counts.keys())
    department_values = list(department_counts.values())

    # Pass data to the template
    context = {
        "verified_alumni": verified_alumni,
        "verified_students": verified_students,
        "not_verified_alumni": not_verified_alumni,
        "not_verified_students": not_verified_students,
        "departments": departments,  
        "department_values": department_values,
        "graduation_year_labels": json.dumps(sorted_graduation_years),  # **Sorted Years**
        "graduation_year_values": json.dumps(sorted_graduation_values),  # **Sorted Values**
    }
    
    return render(request, "authentication/dashboard.html", context)



# Error Page View
def error_view(request):
    return render(request, 'authentication/error.html', {'message': 'An error occurred. Please try again later.'})

import os
from django.conf import settings

def alumni_directory_view(request):
    template_path = os.path.join(settings.BASE_DIR, 'authentication/templates/authentication/alumni_directory.html')
    print("Checking template path:", template_path)  # Debugging
    return render(request, 'authentication/alumni_directory.html')


import os
from django.conf import settings

def jobs_statistics_view(request):
    template_path = os.path.join(settings.BASE_DIR, 'authentication/templates/authentication/jobs_statistics.html')
    print("Checking template path:", template_path)  # Debugging
    return render(request, 'authentication/jobs_statistics.html')
    

import os
from django.conf import settings

def successstory_admin_view(request):
    template_path = os.path.join(settings.BASE_DIR, 'authentication/templates/authentication/successstory_admin.html')
    print("Checking template path:", template_path)  # Debugging
    return render(request, 'authentication/successstory_admin.html')



import os
from django.conf import settings

def survey_view(request):
    template_path = os.path.join(settings.BASE_DIR, 'authentication/templates/authentication/survey.html')
    print("Checking template path:", template_path)  # Debugging
    return render(request, 'authentication/survey.html')


import os
from django.conf import settings

def feedback_view(request):
    template_path = os.path.join(settings.BASE_DIR, 'authentication/templates/authentication/feedback.html')
    print("Checking template path:", template_path)  # Debugging
    return render(request, 'authentication/feedback.html')

import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from firebase_admin import firestore
from django.utils.timezone import now
from django.shortcuts import render
# Helper function to update alumni status
def update_alumni_status():
    current_year = now().year
    current_month = now().month

    alumni_docs = db.collection('alumni').stream()
    for doc in alumni_docs:
        data = doc.to_dict()
        graduation_year = data.get('graduationYear')
        if graduation_year:
            try:
                graduation_year = int(graduation_year)  # Ensure graduationYear is an integer
            except ValueError:
                print(f"Invalid graduationYear format for document {doc.id}")
                continue

            new_status = 'Alumni' if current_year > graduation_year or (current_year == graduation_year and current_month >= 8) else 'Student'
            if data.get('status') != new_status:
                db.collection('alumni').document(doc.id).update({'status': new_status})

# Upload Alumni
@csrf_exempt
def upload_alumni(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            duplicate_emails = []

            for alumni in data:
                name = alumni.get('name')
                email = alumni.get('email')
                degree = alumni.get('degree')
                department = alumni.get('department')
                graduation_year = alumni.get('graduationYear')
                enrollment_details = alumni.get('enrollmentDetails')
                status = alumni.get('status')

                existing_alumni = db.collection('alumni').where('email', '==', email).stream()
                if any(existing for existing in existing_alumni):
                    duplicate_emails.append(email)
                    continue

                alumni_ref = db.collection('alumni').document()
                alumni_ref.set({
                    'name': name,
                    'email': email,
                    'degree': degree,
                    'department': department,
                    'graduationYear': graduation_year,
                    'enrollmentDetails': enrollment_details,
                    'status': status
                })

            update_alumni_status()

            if duplicate_emails:
                return JsonResponse({'message': 'Some emails already exist.', 'duplicates': duplicate_emails}, status=200)
            return JsonResponse({'message': 'Student data uploaded successfully.'}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

# Fetch all alumni
@csrf_exempt
def fetch_alumni(request):
    try:
        update_alumni_status()
        alumni_docs = db.collection('alumni').stream()
        alumni_list = [doc.to_dict() | {'id': doc.id} for doc in alumni_docs]
        return JsonResponse({'status': 'success', 'data': alumni_list})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

# Fetch specific alumni by ID
@csrf_exempt
def fetch_alumni_by_id(request, doc_id):
    try:
        alumni_doc = db.collection('alumni').document(doc_id).get()
        if alumni_doc.exists:
            return JsonResponse({'status': 'success', 'data': alumni_doc.to_dict()})
        return JsonResponse({'status': 'error', 'message': 'Student not found'}, status=404)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

# Edit alumni
@csrf_exempt
def edit_alumni(request, doc_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            db.collection('alumni').document(doc_id).update(data)
            update_alumni_status()
            return JsonResponse({'status': 'success', 'message': 'Student updated successfully'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)

# Delete alumni
@csrf_exempt
def delete_alumni(request, doc_id):
    if request.method == 'DELETE':
        try:
            db.collection('alumni').document(doc_id).delete()
            return JsonResponse({'status': 'success', 'message': 'Student deleted successfully'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)

# Alumni List View
def alumni_list(request):
    update_alumni_status()
    alumni_docs = db.collection('alumni').stream()
    alumni = [doc.to_dict() | {'id': doc.id} for doc in alumni_docs]
    return render(request, 'alumni_directory.html', {'alumni': alumni})

# Upload Excel File
@csrf_exempt
def upload_excel(request):
    import os
    import pandas as pd
    from django.conf import settings

    if request.method == 'POST' and request.FILES.get('file'):
        file = request.FILES['file']
        excel_folder = os.path.join(settings.BASE_DIR, 'excel_files')

        if not os.path.exists(excel_folder):
            os.makedirs(excel_folder)

        temp_file_path = os.path.join(excel_folder, file.name)
        with open(temp_file_path, 'wb') as f:
            for chunk in file.chunks():
                f.write(chunk)

        try:
            data = pd.read_excel(temp_file_path)
            alumni_list = data.to_dict(orient='records')
            alumni_collection = db.collection('alumni')

            added_alumni = []
            for alumni in alumni_list:
                email = alumni.get('email')
                existing_alumni = alumni_collection.where('email', '==', email).stream()

                if not any(existing_alumni):
                    alumni_collection.document().set(alumni)
                    added_alumni.append(alumni)

            update_alumni_status()
            return JsonResponse({'status': 'success', 'message': f'{len(added_alumni)} new Student added successfully.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)



from django.shortcuts import render

def form_view(request):
    return render(request, 'authentication/form.html')


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from firebase.firebase import admin_portal_db as db
import traceback
from datetime import datetime

@csrf_exempt
def save_story(request):
    if request.method == "POST":
        try:
            # Parse the JSON request body
            data = json.loads(request.body)
            title = data.get('title')
            description = data.get('description')
            images = data.get('images')  # Expecting a list of URLs

            # Validate input
            if not title or not description or not isinstance(images, list) or len(images) == 0:
                return JsonResponse({'success': False, 'message': 'Invalid data provided. Images should be a list.'}, status=400)

            # Save to Firestore
            story_ref = db.collection('success_stories').document()
            story_ref.set({
                'title': title,
                'description': description,
                'images': images,
                'created_at': datetime.datetime.utcnow().isoformat()  # Add a timestamp
            })

            return JsonResponse({'success': True, 'message': 'Success story saved successfully!'})
        except Exception as e:
            error_message = f"Error saving story: {e}"
            print(error_message)
            print(traceback.format_exc())  # Log the full traceback
            return JsonResponse({'success': False, 'message': error_message}, status=500)
    else:
        return JsonResponse({'success': False, 'message': 'Invalid request method.'}, status=405)

from django.shortcuts import render
from django.http import JsonResponse
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime

# Initialize Firebase Admin SDK
cred = credentials.Certificate("firebase/alumniconnect-b407a-firebase-adminsdk-35dto-c3375a0345.json")  # Replace with your Firebase Admin SDK path
firebase_admin.initialize_app(cred)

db = firestore.client()

# Get all stories with optional search query filtering
def get_stories(request):
    # Reference to the 'success_stories' collection in Firestore
    stories_ref = db.collection('success_stories')
    query = request.GET.get('query', '').lower()  # Get the query parameter from the URL
    
    # List to hold the stories that match the search criteria
    stories = []

    # Iterate through Firestore documents
    for doc in stories_ref.stream():
        story = doc.to_dict()
        
        # Check if the query is in the title or description (case insensitive)
        if query in story.get('title', '').lower() or query in story.get('description', '').lower():
            story['id'] = doc.id  # Add the Firestore document ID to the story dictionary
            stories.append(story)

    return JsonResponse({'success': True, 'stories': stories})



import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import requests

@csrf_exempt
def edit_story(request, story_id):
    if request.method == 'POST':
        try:
            body = json.loads(request.body.decode('utf-8'))
            title = body.get('title')
            description = body.get('description')
            images = body.get('images', [])

            if not title or not description:
                return JsonResponse({'success': False, 'message': 'Title and description are required.'})

            # Fetch the current story from the database
            current_story = db.collection('success_stories').document(story_id).get().to_dict()
            current_images = current_story.get('images', [])

            # Find images that need to be deleted from Cloudinary
            images_to_delete = list(set(current_images) - set(images))

            # Delete images from Cloudinary
            for image_url in images_to_delete:
                public_id = image_url.split('/')[-1].split('.')[0]
                cloudinary_api_url = f"https://api.cloudinary.com/v1_1/dfowgh13y/resources/image/upload/{public_id}"
                delete_response = requests.delete(cloudinary_api_url)
                if delete_response.status_code != 200:
                    print(f"Failed to delete image: {image_url}")

            # Update the story in the database
            db.collection('success_stories').document(story_id).update({
                'title': title,
                'description': description,
                'images': images,
            })

            return JsonResponse({'success': True, 'message': 'Story updated successfully.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from firebase_admin import firestore


@csrf_exempt
def delete_story(request, story_id):
    if request.method == 'DELETE':
        try:
            # Fetch the story document
            story_ref = db.collection('success_stories').document(story_id)
            story = story_ref.get()
            
            if not story.exists:
                return JsonResponse({'success': False, 'message': 'Story not found.'})
            
            # Remove story document
            story_ref.delete()
            
            return JsonResponse({'success': True, 'message': 'Story deleted successfully.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})




import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import requests

@csrf_exempt
def delete_image_from_story(request, story_id):
    if request.method == 'POST':
        try:
            body = json.loads(request.body.decode('utf-8'))
            image_url = body.get('imageUrl')

            if not image_url:
                return JsonResponse({'success': False, 'message': 'No image URL provided.'})

            # Delete the image from Cloudinary
            public_id = image_url.split('/').pop().split('.')[0]
            delete_url = f"https://api.cloudinary.com/v1_1/dfowgh13y/resources/image/upload/{public_id}"
            delete_response = requests.delete(delete_url)

            if delete_response.status_code == 200:
                # Remove the image from Firestore
                story_ref = db.collection('success_stories').document(story_id)
                story_ref.update({
                    'images': firestore.ArrayRemove([image_url]),
                })
                return JsonResponse({'success': True, 'message': 'Image deleted successfully.'})
            else:
                return JsonResponse({'success': False, 'message': 'Failed to delete image from Cloudinary.'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})


from django.shortcuts import render, redirect
from django.core.files.storage import FileSystemStorage
from django.http import JsonResponse
from .models import Survey

from django.conf import settings

def survey_form_page(request):
    # Check if success message is passed
    success_message = request.GET.get('success', None)
    return render(request, 'authentication/survey_form.html', {'success_message': success_message})

def submit_survey(request):
    if request.method == 'POST':
        # Get form data
        title = request.POST.get('title')
        description = request.POST.get('description')
        poll_question = request.POST.get('poll_question')
        options = request.POST.get('options').split(',')

        # Prepare survey data
        survey_data = {
            'title': title,
            'description': description,
            'poll_question': poll_question,
            'options': [option.strip() for option in options],
            'created_at': firestore.SERVER_TIMESTAMP,
        }

        # Save data to Firestore
        db.collection('surveys').add(survey_data)

        # Redirect back to the form with a success message
        return redirect('/survey_form/?success=Survey posted successfully!')

    return render(request, 'authentication/survey_form.html')

def get_surveys(request):
    try:
        # Retrieve surveys from Firestore
        surveys_ref = db.collection('surveys').stream()
        surveys = [
            {**survey.to_dict(), 'id': survey.id}
            for survey in surveys_ref
        ]
        return JsonResponse({'success': True, 'surveys': surveys}, status=200)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def submit_response(request):
    if request.method == 'POST':
        try:
            survey_id = request.POST.get('survey_id')
            response = request.POST.get('response')
            student_doc_id = request.POST.get('student_doc_id')

            # Save response to Firestore
            db.collection('surveys').document(survey_id).collection('responses').add({
                'response': response,
                'student_doc_id': student_doc_id,
                'created_at': firestore.SERVER_TIMESTAMP,
            })
            return JsonResponse({'success': True, 'message': 'Response submitted successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)

    return JsonResponse({'success': False, 'message': 'Invalid request method'}, status=400)
from django.http import JsonResponse
from google.cloud import firestore

def get_responses(request, survey_id):
    try:
        # Fetch responses for the given survey_id from Firestore
        responses_ref = db.collection('surveys').document(survey_id).collection('responses').stream()
        responses = []

        # Loop through the responses and get student details
        for response in responses_ref:
            response_data = response.to_dict()
            student_doc_id = response_data.get('student_doc_id')

            # Fetch student details directly from the response data
            student_name = response_data.get('student_name', 'Unknown')
            student_degree = response_data.get('degree', 'Not Provided')
            student_graduation_year = response_data.get('graduation_year', 'Not Provided')
            student_email = student_doc_id  # Assuming student_doc_id is the email

            responses.append({
                'id': response.id,
                'response': response_data.get('response'),
                'student_doc_id': student_doc_id,
                'student_name': student_name,
                'student_degree': student_degree,
                'student_graduation_year': student_graduation_year,
                'student_email': student_email,
                'created_at': response_data.get('created_at').astimezone().strftime('%d %B %Y at %I:%M:%S %p') if response_data.get('created_at') else 'N/A',
            })
        
        return JsonResponse({'success': True, 'responses': responses}, status=200)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


from django.http import JsonResponse
from django.shortcuts import render
from firebase_admin import firestore


def fetch_feedback(request):
    """Fetch feedback data from Firestore and return as JSON."""
    try:
        search_query = request.GET.get("search", "").lower()
        feedback_docs = db.collection("feedback").stream()
        feedback_list = []

        for feedback in feedback_docs:
            feedback_data = feedback.to_dict()
            student_doc_id = feedback_data.get("student_doc_id")

            # Fetch student details using student_doc_id from 'alumni' collection
            student_doc = db.collection("alumni").document(student_doc_id).get()
            if student_doc.exists:
                student_data = student_doc.to_dict()
                feedback_data["student_name"] = student_data.get("name", "Unknown")
                feedback_data["degree"] = student_data.get("degree", "Not Provided")
                feedback_data["graduationYear"] = student_data.get("graduationYear", "Not Provided")

                # Apply search filtering
                if search_query and search_query not in feedback_data["student_name"].lower():
                    continue  # Skip if search query doesn't match

            feedback_list.append(feedback_data)

        return JsonResponse({"success": True, "feedback": feedback_list}, status=200)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)



#NEWSLETTER
import datetime
import requests
from django.shortcuts import render, redirect
from firebase_admin import firestore



# Cloudinary configurations
CLOUDINARY_URL = 'https://api.cloudinary.com/v1_1/dfowgh13y/upload'
UPLOAD_PRESET = 'AlumniConnect'

def newsletter_form_page(request):
    """Handles the newsletter form submissions."""
    if request.method == 'POST':
        # Get form data
        title = request.POST.get('title')
        description = request.POST.get('description')
        uploaded_file = request.FILES.get('images')

        # Upload image to Cloudinary
        image_url = None
        if uploaded_file:
            files = {'file': uploaded_file}
            data = {'upload_preset': UPLOAD_PRESET}
            response = requests.post(CLOUDINARY_URL, files=files, data=data)
            if response.status_code == 200:
                image_url = response.json().get('secure_url')
            else:
                return render(request, 'authentication/newsletter_form.html', {
                    'error': 'Image upload failed. Please try again.',
                    'success': False,
                })

        # Add the data to Firestore
        doc_data = {
            'title': title,
            'description': description,
            'created_time': datetime.datetime.now(),
            'image_url': image_url
        }
        db.collection('newsletter').add(doc_data)

        # Pass success flag
        return render(request, 'authentication/newsletter_form.html', {'success': True})

    return render(request, 'authentication/newsletter_form.html', {'success': False})
    

def newsletter_view(request):
    """Displays the list of newsletters."""
    newsletters = db.collection('newsletter').stream()
    data = [
        {
            'id': doc.id,
            'title': doc.get('title'),
            'description': doc.get('description'),
            'created_time': doc.get('created_time').strftime('%Y-%m-%d %H:%M:%S'),
            'image_url': doc.get('image_url')
        }
        for doc in newsletters
    ]
    return render(request, 'authentication/newsletter.html', {'newsletters': data})
    
# Existing view for deleting newsletters
def newsletter_delete(request, newsletter_id):
    db.collection('newsletter').document(newsletter_id).delete()
    return redirect('newsletter')

from django.http import JsonResponse

def get_newsletter(request, newsletter_id):
    doc_ref = db.collection('newsletter').document(newsletter_id)
    doc = doc_ref.get()

    if not doc.exists:
        return JsonResponse({'error': 'Newsletter not found'}, status=404)

    data = doc.to_dict()
    return JsonResponse(data)


from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import datetime
import requests

CLOUDINARY_URL = 'https://api.cloudinary.com/v1_1/dfowgh13y/upload'
UPLOAD_PRESET = 'AlumniConnect'

@csrf_exempt
def update_newsletter(request, newsletter_id):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        uploaded_file = request.FILES.get('image')

        # Fetch existing newsletter
        doc_ref = db.collection('newsletter').document(newsletter_id)
        doc = doc_ref.get()

        if not doc.exists:
            return JsonResponse({'error': 'Newsletter not found'}, status=404)

        newsletter = doc.to_dict()

        # Upload new image if provided
        image_url = newsletter.get('image_url')
        if uploaded_file:
            response = requests.post(
                CLOUDINARY_URL,
                files={'file': uploaded_file},
                data={'upload_preset': UPLOAD_PRESET},
            )
            if response.status_code == 200:
                image_url = response.json().get('secure_url')

        # Update Firestore document
        doc_ref.update({
            'title': title,
            'description': description,
            'image_url': image_url,
            'created_time': datetime.datetime.now(),
        })
        return JsonResponse({'message': 'Newsletter updated successfully'})


from django.shortcuts import render, redirect
from firebase.firebase import admin_portal_db

# Display student requests in a table
def admin_requests_view(request):
    requests_docs = admin_portal_db.collection('requests').stream()
    student_requests = []

    for doc in requests_docs:
        student_data = doc.to_dict()
        student_data['id'] = doc.id  # Add document ID for actions
        student_requests.append(student_data)

    return render(request, 'authentication/requests.html', {'student_requests': student_requests})

# Accept student request
def accept_request_view(request, request_id):
    if request.method == 'POST':
        doc_ref = admin_portal_db.collection('requests').document(request_id)
        student_data = doc_ref.get().to_dict()

        if student_data:
            # Move data to the 'alumni' collection
            admin_portal_db.collection('alumni').add(student_data)
            # Delete from the 'requests' collection
            doc_ref.delete()

    return redirect('admin_requests')

# Reject student request
def reject_request_view(request, request_id):
    if request.method == 'POST':
        admin_portal_db.collection('requests').document(request_id).delete()
    return redirect('admin_requests')

import datetime
from django.shortcuts import render
from firebase.firebase import student_portal_db  # Import Firestore instance
import datetime
from django.shortcuts import render
from firebase.firebase import student_portal_db  # Import Firestore instance

def jobs_statistics(request):
    jobs_ref = student_portal_db.collection('job')  # Fetch from student DB

    try:
        jobs = list(jobs_ref.stream())  # Convert generator to list
    except Exception as e:
        print("Error fetching jobs:", e)
        jobs = []

    total_jobs = len(jobs)  # Count total jobs

    company_counts = {}  # Count jobs per company
    job_type_counts = {}  # Count jobs per job type
    active_applications = 0
    current_date = datetime.datetime.now().date()

    for job in jobs:
        job_data = job.to_dict()

        # Count jobs per company
        company_name = job_data.get('company_name', 'Unknown Company')
        company_counts[company_name] = company_counts.get(company_name, 0) + 1

        # Count jobs per job type
        job_type = job_data.get('job_type', 'Other')
        job_type_counts[job_type] = job_type_counts.get(job_type, 0) + 1

        # Check for active job applications
        if 'deadline' in job_data:
            try:
                deadline_date = datetime.datetime.strptime(job_data['deadline'], "%Y-%m-%d").date()
                if deadline_date >= current_date:
                    active_applications += 1
            except ValueError:
                pass  # Ignore invalid date formats

    total_companies = len(company_counts)

    # Convert data to lists for Chart.js
    company_labels = list(company_counts.keys())  # Company names
    company_values = list(company_counts.values())  # Job counts

    job_type_labels = list(job_type_counts.keys())  # Job types
    job_type_values = list(job_type_counts.values())  # Job counts

    print("Company Data:", company_labels, company_values)  # Debugging
    print("Job Type Data:", job_type_labels, job_type_values)  # Debugging

    # Pass data to template
    context = {
        'total_jobs': total_jobs,
        'total_companies': total_companies,
        'active_applications': active_applications,
        'company_labels': company_labels,  # Chart Labels
        'company_values': company_values,  # Chart Data
        'job_type_labels': job_type_labels,  # Chart Labels
        'job_type_values': job_type_values  # Chart Data
    }

    return render(request, 'authentication/jobs_statistics.html', context)

