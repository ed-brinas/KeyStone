<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;


// Redirect the root URL to the users index page.
Route::get('/', function () {
    return redirect()->route('users.index');
});

// User management routes
Route::prefix('users')->name('users.')->controller(UserController::class)->group(function () {
    Route::get('/', 'index')->name('index');
    Route::post('/', 'store')->name('store');
    Route::put('/{guid}', 'update')->name('update');
    Route::post('/{guid}/reset-password', 'resetPassword')->name('resetPassword');
    Route::get('/download-pdf/{filename}', 'downloadPdf')->name('download-pdf');
});
