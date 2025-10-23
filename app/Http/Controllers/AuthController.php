<?php

namespace App\Http\Controllers;

use App\Services\AdService;
use Illuminate\Http\Request; // <-- Use standard request
use Illuminate\Support\Facades\Validator; // <-- For manual validation
use Illuminate\Validation\Rule; // <-- For domain rule
use App\Models\User;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Hash;

/**
* @OA\Tag(name="Authentication", description="User authentication and logout endpoints.")
*/
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
    * summary="Authenticate user and return Sanctum token",
    * tags={"Authentication"},
    * @OA\RequestBody(
    * required=true,
    * @OA\JsonContent(
    * required={"username", "password", "domain"},
    * @OA\Property(property="username", type="string", example="jdoe"),
    * @OA\Property(property="password", type="string", example="P@ssw0rd123!!"),
    * @OA\Property(property="domain", type="string", example="ncc.lab")
    * )
    * ),
    * @OA\Response(response=200, description="Login successful",
    * @OA\JsonContent(
    * @OA\Property(property="token", type="string"),
    * @OA\Property(property="user", type="object",
    * @OA\Property(property="name", type="string"),
    * @OA\Property(property="email", type="string"),
    * @OA\Property(property="roles", type="array", @OA\Items(type="string"))
    * )
    * )
    * ),
    * @OA\Response(response=401, description="Invalid credentials"),
    * @OA\Response(response=403, description="Access denied"),
    * @OA\Response(response=500, description="Internal server error")
    * )
    */
    public function login(Request $request): JsonResponse
    {
        // --- Start Manual Validation ---
        $validator = Validator::make($request->all(), [
            'username' => 'required|string',
            'password' => 'required|string',
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))],
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $credentials = $validator->validated();
        // --- End Manual Validation ---

        $domain = $credentials['domain'];
        $username = $credentials['username'];
        $password = $credentials['password'];

        try {
            // 1. Authenticate against AD
            $adUser = $this->adService->login($domain, $username, $password);

            if (!$adUser) {
                return response()->json(['message' => 'Invalid credentials'], 401);
            }

            // 2. Get AD group-based roles (as normalized strings)
            $roles = $this->adService->getRolesForUser($adUser, $domain);

            if (empty($roles)) {
                Log::warning("Login failed for user {$username}: User is not a member of any required access groups.");
                return response()->json(['message' => 'Access Denied: You do not have permission to access this application.'], 403);
            }

            // 3. Find or create the local user
            $user = User::updateOrCreate(
                ['username' => $adUser->getFirstAttribute('samaccountname')],
                [
                    'name' => $adUser->getFirstAttribute('displayname'),
                    'email' => $adUser->getFirstAttribute('mail') ?? $username.'@'.$domain, 
                    'password' => Hash::make(Str::random(40))
                ]
            );

            // 4. Create and return Sanctum token
            $token = $user->createToken('ad-api-token', $roles)->plainTextToken;

            return response()->json([
                'token' => $token,
                'user' => [
                    'name' => $user->name,
                    'email' => $user->email,
                    'roles' => $roles
                ]
            ]);

        } catch (\Exception $e) {
            Log::error("General error during login: " . $e->getMessage());
            return response()->json(['message' => 'An internal server error occurred.'], 500);
        }
    }

    /**
    * @OA\Post(
    * path="/api/v1/logout",
    * summary="Logout the current authenticated user",
    * tags={"Authentication"},
    * security={{"sanctum": {}}},
    * @OA\Response(response=204, description="Logout successful")
    * )
    */
    public function logout(Request $request): JsonResponse
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json([], 204);
    }
}

