{{-- resources/views/auth/login.blade.php --}}
@extends('layouts.app')

@section('title', 'KeyStone - Login')

@section('content')
    {{-- This screen is the entry point for the application --}}
    <div id="login-page" class="screen">
        <div class="login-box text-center shadow-sm">
            <h1 class="h3 mb-3 fw-normal">Active Directory Management</h1>
            <div class="alert alert-warning text-start small mb-4">
                <strong>Notice:</strong> Access to this system is restricted to authorized administrators.
            </div>
            {{-- Form submission will be handled by your app.js --}}
            <form id="login-form" class="text-start">
                <div class="mb-3">
                    <label for="login-domain" class="form-label">Domain</label>
                    <select id="login-domain" class="form-select" required></select>
                </div>
                <div class="mb-3">
                    <label for="login-username" class="form-label">Username</label>
                    <input type="text" class="form-control" id="login-username" required>
                </div>
                <div class="mb-3">
                    <label for="login-password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="login-password" required>
                </div>
                <button type="submit" class="w-100 btn btn-lg btn-primary">Login</button>
                <div id="login-error" class="alert alert-danger mt-3 d-none" role="alert"></div>
            </form>
        </div>
    </div>
@endsection
