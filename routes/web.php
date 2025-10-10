<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

// MODIFIED START - 2025-10-10 19:41 - Replaced generic resource route with specific named routes to match the view.
// Redirect the root URL to the users index page.
Route::get('/', function () {
    return redirect()->route('users.index');
});

// User management routes
Route::get('/users', [UserController::class, 'index'])->name('users.index');
Route::get('/users/create', [UserController::class, 'create'])->name('users.create');
Route::post('/users', [UserController::class, 'store'])->name('users.store');

// Route for showing the edit form (Phase 3 Stub)
Route::get('/users/{guid}/edit', [UserController::class, 'edit'])->name('users.edit');

// Route for unlocking a user account
Route::post('/users/{guid}/unlock', [UserController::class, 'unlock'])->name('users.unlock');

// Route for toggling user account status (enable/disable)
Route::post('/users/{guid}/toggle-status', [UserController::class, 'toggleStatus'])->name('users.toggle-status');
// MODIFIED END - 2025-10-10 19:41

