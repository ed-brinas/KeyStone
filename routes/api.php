<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\PasswordController;
use App\Http\Controllers\UserController;
use Illuminate\Support\Facades\Route;

// --- Public Routes ---
Route::post('/v1/login', [AuthController::class, 'login']);

// --- Protected Routes ---
Route::middleware('auth:sanctum')->prefix('v1')->group(function () {
    // Auth
    Route::post('/logout', [AuthController::class, 'logout']);

    // User Management
    Route::post('/users', [UserController::class, 'store'])->middleware('permission:create-user');
    Route::get('/users/{user}', [UserController::class, 'show'])->middleware('permission:view-user');
    Route::put('/users/{user}', [UserController::class, 'update'])->middleware('permission:edit-user');

    // User Status Control
    Route::patch('/users/{user}/enable', [UserController::class, 'enable'])->middleware('permission:edit-user-status');
    Route::patch('/users/{user}/disable', [UserController::class, 'disable'])->middleware('permission:edit-user-status');
    Route::patch('/users/{user}/unlock', [UserController::class, 'unlock'])->middleware('permission:edit-user-status');

    // Password Management
    Route::post('/users/{user}/reset-password', [PasswordController::class, 'resetStandardPassword'])->middleware('permission:reset-password');
    Route::post('/users/{user}/reset-admin-password', [PasswordController::class, 'resetAdminPassword'])->middleware('permission:reset-admin-password');
});