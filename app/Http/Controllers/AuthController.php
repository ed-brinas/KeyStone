<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Models\User as LocalUser;
use App\Services\AdService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use LdapRecord\Container;

class AuthController extends Controller
{
    protected AdService $adService;

    public function __construct(AdService $adService)
    {
        $this->adService = $adService;
    }

    /**
     * @OA\Post(
     * path="/api/v1/login",
     * summary="Authenticate user against Active Directory",
     * tags={"Authentication"},
     * @OA\RequestBody(
     * required=true,
     * @OA\JsonContent(
     * required={"username", "password", "domain"},
     * @OA\Property(property="username", type="string", example="jdoe"),
     * @OA\Property(property="password", type="string", format="password", example="Password123"),
     * @OA\Property(property="domain", type="string", example="ncc.local")
     * )
     * ),
     * @OA\Response(
     * response=200,
     * description="Successful authentication",
     * @OA\JsonContent(
     * @OA\Property(property="token", type="string")
     * )
     * ),
     * @OA\Response(response=401, description="Invalid credentials or not authorized"),
     * @OA\Response(response=422, description="Validation error")
     * )
     */
    public function login(LoginRequest $request): JsonResponse
    {
        $domain = $request->input('domain');
        $username = $request->input('username');
        $password = $request->input('password');

        $connectionName = str_replace('.', '_', $domain);
        Container::setDefault($connectionName);

        if (!$this->adService->authenticate($username, $password)) {
            throw ValidationException::withMessages([
                'username' => ['The provided credentials do not match our records.'],
            ]);
        }
        
        $adUser = $this->adService->findUserByUsername($username);

        if (!$adUser || !$this->adService->isUserAuthorizedToLogin($adUser)) {
             throw ValidationException::withMessages([
                'username' => ['You are not authorized to access this application.'],
            ]);
        }

        // Find or create a local user record
        $localUser = LocalUser::firstOrCreate(
            ['username' => $adUser->getSamAccountName()],
            [
                'name' => $adUser->getDisplayName(),
                'email' => $adUser->getEmail(),
                'password' => Hash::make(str()->random(20)) // Set a random password, not used for login
            ]
        );

        // Sync roles and permissions
        $this->adService->syncUserRolesAndPermissions($localUser, $adUser);

        // Create API token
        $token = $localUser->createToken('api-token')->plainTextToken;

        return response()->json(['token' => $token]);
    }

    /**
     * @OA\Post(
     * path="/api/v1/logout",
     * summary="Log out the current user",
     * tags={"Authentication"},
     * security={{"sanctum":{}}},
     * @OA\Response(response=204, description="Successfully logged out")
     * )
     */
    public function logout(Request $request): JsonResponse
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json([], 204);
    }
}
