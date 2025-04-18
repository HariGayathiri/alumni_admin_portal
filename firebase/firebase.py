import firebase_admin
from firebase_admin import credentials, firestore

# Load Firebase credentials
admin_portal_cred = credentials.Certificate('firebase/alumniconnect-b407a-firebase-adminsdk-35dto-c3375a0345.json')

# Initialize the Firebase app with a unique name
admin_portal_app = firebase_admin.initialize_app(admin_portal_cred, name='AlumniConnect')

# Create a Firestore client using the initialized app
admin_portal_db = firestore.client(admin_portal_app)


student_portal_cred = credentials.Certificate('firebase/connectplatform-b89b4-268988303f18.json')
student_portal_app = firebase_admin.initialize_app(student_portal_cred, name='ConnectPlatform')
student_portal_db = firestore.client(student_portal_app)