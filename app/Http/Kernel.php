<?php

use App\Http\Middleware\AdminAuth;
use App\Http\Middleware\GateGeneral;
use App\Http\Middleware\GateHigh;


protected $middlewareAliases = [
    // ...
    'auth.admin' => AdminAuth::class,
    'gate.general' => GateGeneral::class,
    'gate.high' => GateHigh::class,
];
