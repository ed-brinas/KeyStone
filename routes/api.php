<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;
use App\Http\Controllers\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// --- Authentication Routes ---
// These routes handle user login, logout, and session status.
Route::controller(AuthController::class)->prefix('auth')->name('auth.')->group(function () {
    Route::post('/login', 'login')->name('login');
    Route::post('/logout', 'logout')->name('logout');
    Route::get('/me', 'me')->name('me'); // Endpoint to check auth status
});


// --- Standalone Routes ---
// Route to get application configuration (domains, groups, etc.).
Route::get('/config', [UserController::class, 'getConfig'])->name('config');


// --- User Management Group ---
// All routes related to managing users are grouped under the '/users' prefix
// and are protected by the 'auth' middleware.
Route::middleware('auth:sanctum')->prefix('users')->name('users.')->controller(UserController::class)->group(function () {
    // GET /api/users - List users
    Route::get('/', 'index')->name('index');

    // POST /api/users - Create a new user
    Route::post('/', 'store')->name('store');

    // GET /api/users/show - Get details for a single user
    Route::get('/show', 'show')->name('show');

    // PUT /api/users - Update an existing user
    Route::put('/', 'update')->name('update');

    // User action routes
    Route::post('/reset-password', 'resetPassword')->name('reset-password');
    Route::post('/reset-admin-password', 'resetAdminPassword')->name('reset-admin-password');
    Route::post('/unlock-account', 'unlockAccount')->name('unlock-account');
    Route::post('/disable-account', 'disableAccount')->name('disable-account');
    Route::post('/enable-account', 'enableAccount')->name('enable-account');
});

