from django.shortcuts import render

def ver_dashboard(request):
    return render(request, 'dashboard/contador.html')
