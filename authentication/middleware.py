from django.shortcuts import redirect

class AdminAuthMiddleware:
    """
    Middleware to ensure only authenticated admins can access specific pages.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # List of routes that require authentication
        restricted_routes = ['/dashboard/']

        if request.path in restricted_routes and not request.session.get('is_authenticated', False):
            return redirect('login')

        response = self.get_response(request)
        return response
