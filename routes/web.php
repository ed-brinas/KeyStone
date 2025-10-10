<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

// MODIFIED START - 2025-10-10 19:27 - Added a redirect from root to the users index page.
Route::get('/', function () {
    return redirect()->route('users.index');
});
// MODIFIED END - 2025-10-10 19:27

// MODIFIED START - 2025-10-10 19:27 - Ensured all routes required by the new view are correctly defined.
// User search and listing
Route::get('/users', [UserController::class, 'index'])->name('users.index');

// Routes for creating and storing a new user (Phase 3)
Route::get('/users/create', [UserController::class, 'create'])->name('users.create');
Route::post('/users', [UserController::class, 'store'])->name('users.store');

// Route for the user edit page (Phase 3)
Route::get('/users/{guid}/edit', [UserController::class, 'edit'])->name('users.edit');

// Core User Action Routes (Phase 2)
Route::post('/users/{guid}/toggle-status', [UserController::class, 'toggleStatus'])->name('users.toggle-status');
Route::post('/users/{guid}/unlock', [UserController::class, 'unlock'])->name('users.unlock');
// MODIFIED END - 2025-10-10 19:27

