<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;


// Redirect the root URL to the users index page.
Route::get('/', function () {
    return redirect()->route('users.index');
});

// User Management Routes
Route::resource('users', UserController::class)->only(['index', 'store', 'update']);
Route::post('/users/{guid}/reset-password', [UserController::class, 'resetPassword'])->name('users.resetPassword');
