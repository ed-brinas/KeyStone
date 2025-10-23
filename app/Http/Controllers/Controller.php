<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;

/**
* @OA\OpenApi(
* @OA\Info(
* version="1.0.0",
* title="KeyStone AD Management API",
* description="API for managing on-premise Active Directory (Multi-Domain)",
* @OA\Contact(email="admin@keystone.app", name="Keystone Admin")
* ),
* @OA\Server(url=L5_SWAGGER_CONST_HOST, description="Local API Server"),
* security={{"sanctum": {}}}
* )
* @OA\SecurityScheme(
* securityScheme="sanctum",
* type="http",
* scheme="bearer",
* bearerFormat="JWT",
* description="Enter token in format: Bearer {token}"
* )
*/
class Controller extends BaseController
{
    use AuthorizesRequests, ValidatesRequests;
}
