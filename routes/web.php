<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController; // <-- Add this line

Route::get('/', function () {
    return view('welcome');
});

// Add this route for our user search page
Route::get('/users', [UserController::class, 'index'])->name('users.index');
