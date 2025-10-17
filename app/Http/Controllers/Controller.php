<?php

namespace App\Http\Controllers;

/**
 * @OA\Info(
 *      version="1.0.0",
 *      title="Keystone API",
 *      description="Unified API documentation for authentication and user management.",
 *      @OA\Contact(email="support@example.com")
 * )
 *
 * @OA\Server(
 *      url="http://localhost:8000",
 *      description="Local API Server"
 * )
 *
 * @OA\SecurityScheme(
 *      securityScheme="bearerAuth",
 *      type="http",
 *      scheme="bearer",
 *      bearerFormat="JWT"
 * )
 */
abstract class Controller
{

}

