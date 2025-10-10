<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController; // <-- Add this line

Route::get('/', function () {
    return view('welcome');
});

// User search and listing
Route::get('/users', [UserController::class, 'index'])->name('users.index');

// MODIFIED START - 2025-10-10 19:09 - Added routes for creating and storing a new user
Route::get('/users/create', [UserController::class, 'create'])->name('users.create');
Route::post('/users', [UserController::class, 'store'])->name('users.store');
// MODIFIED END - 2025-10-10 19:09

// Placeholder for the user edit page (Module 2+)
Route::get('/users/{guid}/edit', [UserController::class, 'edit'])->name('users.edit');

// Core User Action Routes (Module 2)
Route::post('/users/{guid}/toggle-status', [UserController::class, 'toggleStatus'])->name('users.toggle-status');
Route::post('/users/{guid}/unlock', [UserController::class, 'unlock'])->name('users.unlock');

