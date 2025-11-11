<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\HealthController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\PasswordController;

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
    Route::post('/logout', 'logout')->name('logout')->middleware('auth:sanctum');
    Route::get('/me', 'me')->name('me')->middleware('auth:sanctum');
});

// --- Standalone Routes ---
// Route to get application configuration (domains, groups, etc.).
Route::get('v1/config', [UserController::class, 'getConfig'])->name('config');


// Protected routes (require auth token)
Route::middleware('auth:sanctum')->prefix('v1')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);

    // User Management
    Route::apiResource('users', UserController::class)->only(['index', 'show', 'store', 'update']);
    Route::post('users/{samAccountName}/enable', [UserController::class, 'enableAccount']);
    Route::post('users/{samAccountName}/disable', [UserController::class, 'disableAccount']);
    Route::post('users/{samAccountName}/unlock', [UserController::class, 'unlockAccount']);

    // Password Management
    Route::post('passwords/reset-standard', [PasswordController::class, 'resetPassword']);
});
