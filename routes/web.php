<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController; // <-- Add this line

Route::get('/', function () {
    return view('welcome');
});

// User search and listing
Route::get('/users', [UserController::class, 'index'])->name('users.index');

// Placeholder for the user edit page (Module 2+)
Route::get('/users/{guid}/edit', [UserController::class, 'edit'])->name('users.edit');

// Core User Action Routes (Module 2)
Route::post('/users/{guid}/toggle-status', [UserController::class, 'toggleStatus'])->name('users.toggle-status');
Route::post('/users/{guid}/unlock', [UserController::class, 'unlock'])->name('users.unlock');
