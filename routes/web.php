<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

Route::get('/', function () {
    return view('welcome');
});

// Assuming you want the user list to be the main page for now
Route::get('/users', [UserController::class, 'index'])->name('users.index');
Route::get('/users/create', [UserController::class, 'create'])->name('users.create');
Route::post('/users', [UserController::class, 'store'])->name('users.store');

// MODIFIED START - 2025-10-10 19:23
// Removed incorrect toggle-status route and added separate routes for enable and disable actions.
// Route::post('/users/{guid}/toggle-status', [UserController::class, 'toggleStatus'])->name('users.toggle-status');
Route::post('/users/{guid}/enable', [UserController::class, 'enable'])->name('users.enable');
Route::post('/users/{guid}/disable', [UserController::class, 'disable'])->name('users.disable');
// MODIFIED END - 2025-10-10 19:23

Route::post('/users/{guid}/unlock', [UserController::class, 'unlock'])->name('users.unlock');
