<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;


// Redirect the root URL to the users index page.
Route::get('/', function () {
    return redirect()->route('users.index');
});

// User management routes
Route::get('/users', [UserController::class, 'index'])->name('users.index');
Route::post('/users', [UserController::class, 'store'])->name('users.store');
Route::put('/users/{guid}', [UserController::class, 'update'])->name('users.update');

// User account actions
Route::post('/users/{guid}/toggle-status', [UserController::class, 'toggleStatus'])->name('users.toggle-status');
Route::post('/users/{guid}/unlock', [UserController::class, 'unlock'])->name('users.unlock');
// MODIFIED START - 2025-10-10 23:08 - Updated timestamp for password reset route.
Route::post('/users/{guid}/reset-password', [UserController::class, 'resetPassword'])->name('users.resetPassword');
// MODIFIED END - 2025-10-10 23:08
