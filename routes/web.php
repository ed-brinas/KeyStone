<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/', [AuthController::class, 'splash'])->name('splash');
Route::get('/login', [AuthController::class, 'showLogin'])->name('login');
Route::post('/login', [AuthController::class, 'login'])->name('login.post');
Route::post('/logout', [AuthController::class, 'logout'])->name('logout');


Route::middleware(['auth.admin','gate.general'])->group(function () {
Route::get('/dashboard', [UserController::class, 'index'])->name('dashboard');
Route::post('/user/{dn}/lock', [UserController::class, 'lock']);
Route::post('/user/{dn}/enable', [UserController::class, 'enable']);
Route::post('/user', [UserController::class, 'store']);
Route::put('/user/{dn}', [UserController::class, 'update']);
});


Route::middleware(['auth.admin','gate.high'])->group(function () {
Route::post('/user/{sam}/admin-twin', [UserController::class, 'createAdminTwin']);
Route::get('/audit', [AuditController::class, 'index'])->name('audit.index');
Route::get('/pdf/user/{sam}', [UserController::class, 'downloadSummary'])->name('pdf.user.summary');
});


Route::get('/self-service', [PasswordController::class, 'showForm']);
Route::post('/self-service/reset', [PasswordController::class, 'reset']);
