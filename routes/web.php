<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\LoginController;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| These routes handle displaying the application's views.
|
*/

// Route to display the login form. The 'guest' middleware prevents logged-in users from seeing it.
Route::get('login', [LoginController::class, 'showLoginForm'])->middleware('guest')->name('login');

// The main application route. The 'auth' middleware protects it,
// ensuring only authenticated users can access it.
Route::get('/', function () {
    return view('app'); // This will load resources/views/app.blade.php
})->middleware('auth')->name('home');

