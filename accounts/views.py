from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.core.exceptions import PermissionDenied

from vendor.forms import VendorForm
from .forms import UserForm
from .models import User, UserProfile
from .utils import detect_user


# Restrict the vendor from accessing the customer page
def check_role_vendor(user):
    if user.role == 1:
        return True
    else:
        raise PermissionDenied


# Restrict the customer from accessing the vendor page
def check_role_customer(user):
    if user.role == 2:
        return True
    else:
        raise PermissionDenied


def register_user(request):
    if request.user.is_authenticated:
        messages.warning(request, 'You are already logged in')
        return redirect('accounts:dashboard')
    elif request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            # Create the user using the form

            # user = form.save(commit=False)
            # user.set_password(form.cleaned_data['password'])
            # user.role = User.CUSTOMER
            # user.save()

            # Create the user using the create_user method
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            user = User.objects.create_user(
                first_name=first_name, last_name=last_name, username=username, email=email, password=password
            )
            user.role = User.CUSTOMER
            user.save()
            messages.success(request, 'Your account has been registered successfully.')
            return redirect('accounts:register_user')
        else:
            print('Invalid form')
            print(form.errors)
    else:
        form = UserForm()

    context = {
        'form': form
    }

    return render(request, 'accounts/register_user.html', context)


def register_vendor(request):
    if request.user.is_authenticated:
        messages.warning(request, 'You are already logged in')
        return redirect('accounts:dashboard')
    elif request.method == 'POST':
        form = UserForm(request.POST)
        v_form = VendorForm(request.POST, request.FILES)
        if form.is_valid() and v_form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.role = User.VENDOR
            user.save()
            vendor = v_form.save(commit=False)
            vendor.user = user
            user_profile = UserProfile.objects.get(user=user)
            vendor.user_profile = user_profile
            vendor.save()
            messages.success(request, 'Your account has been registered successfully. Please wait for the approval.')
            return redirect('accounts:register_vendor')
        else:
            print('invalid form')
            print(form.errors)
    else:
        form = UserForm()
        v_form = VendorForm()

    context = {
        'form': form,
        'v_form': v_form,
    }

    return render(request, 'accounts/register_vendor.html', context)


def login(request):
    if request.user.is_authenticated:
        messages.warning(request, 'You are already logged in')
        return redirect('accounts:my_account')
    elif request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        print(email)

        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            messages.success(request, 'You are now logged in.')
            return redirect('accounts:my_account')
        else:
            messages.error(request, 'Invalid login credentials')
            return redirect('accounts:login')

    return render(request, 'accounts/login.html')


def logout(request):
    auth.logout(request)
    messages.info(request, 'You are logged out.')
    return redirect('accounts:login')


@login_required(login_url='accounts:login')
def my_account(request):
    user = request.user
    redirect_url = detect_user(user)
    print(f"redirect: {redirect_url}")
    return redirect(redirect_url)


@login_required(login_url='accounts:login')
@user_passes_test(check_role_customer)
def cust_dashboard(request):
    return render(request, 'accounts/cust_dashboard.html')


@login_required(login_url='accounts:login')
@user_passes_test(check_role_vendor)
def vendor_dashboard(request):
    return render(request, 'accounts/vendor_dashboard.html')
