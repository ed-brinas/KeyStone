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

// Public routes
Route::post('/v1/login', [AuthController::class, 'login'])->name('login');
Route::get('/v1/health', [HealthController::class, 'check']);

// Protected routes (require auth token)
Route::middleware('auth:sanctum')->prefix('v1')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);

    // User Management
    Route::apiResource('users', UserController::class)->only(['index', 'show', 'store', 'update']);
    Route::post('users/{samAccountName}/enable', [UserController::class, 'enableAccount']);
    Route::post('users/{samAccountName}/disable', [UserController::class, 'disableAccount']);
    Route::post('users/{samAccountName}/unlock', [UserController::class, 'unlockAccount']);

    // Password Management
    Route::post('passwords/reset-standard', [PasswordController::class, 'resetStandardPassword']);
    Route::post('passwords/reset-admin', [PasswordController::class, 'resetAdminPassword']);
});
