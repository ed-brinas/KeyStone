<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|--------------------------------------------------------------------------
*/

// Existing user routes remain unchanged

Route::prefix('users')->group(function () {
    Route::get('/', [UserController::class, 'index'])->name('users.index');
    Route::post('/toggle-status/{guid}', [UserController::class, 'toggleStatus'])->name('users.toggle-status');
    Route::post('/unlock/{guid}', [UserController::class, 'unlock'])->name('users.unlock');
    Route::post('/reset-password/{guid}', [UserController::class, 'resetPassword'])->name('users.resetPassword');
});
