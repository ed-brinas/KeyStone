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
Route::put('/users/{guid}', [UserController::class, 'update'])->name('users.update');
Route::post('/users/{guid}/reset-password', [UserController::class, 'resetPassword'])->name('users.resetPassword');

