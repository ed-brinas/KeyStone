<?php

namespace App\Http\Controllers;

use App\Services\AdService;
use Illuminate\Http\Request; // <-- Use standard request
use Illuminate\Support\Facades\Validator; // <-- For manual validation
use Illuminate\Validation\Rule; // <-- For domain rule
use App\Models\User as LocalUser;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Hash;

/**
 * @OA\OpenApi(
 * @OA\Info(
 * version="1.0.0",
 * title="KeyStone AD Management API",
 * description="API for managing on-premise Active Directory",
 * @OA\Contact(email="support@example.com")
 * ),
 * @OA\Server(
 * url=L5_SWAGGER_CONST_HOST,
 * description="Local API Server"
 * ),
 * @OA\SecurityScheme(
 * securityScheme="sanctum",
 * type="http",
 * scheme="bearer",
 * bearerFormat="JWT",
 * description="Enter token in format: Bearer <token>"
 * ),
 * security={{"sanctum":{}}}
 * )
 * @OA\Tag(
 * name="Authentication",
 * description="Handles user authentication and token management."
 * )
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
     * summary="Authenticate user and get API token",
     * tags={"Authentication"},
     * @OA\RequestBody(
     * required=true,
     * description="User credentials for AD login",
     * @OA\JsonContent(ref="#/components/schemas/LoginRequest")
     * ),
     * @OA\Response(
     * response=200,
     * description="Authentication successful",
     * @OA\JsonContent(
     * @OA\Property(property="token", type="string", example="1|abc..."),
     * @OA\Property(property="user", type="object",
     * @OA\Property(property="name", type="string", example="John Doe"),
     * @OA\Property(property="email", type="string", example="jdoe@ncc.lab"),
     * @OA\Property(property="roles", type="array", @OA\Items(type="string"), example={"l3", "domain admins", "default"})
     * )
     * )
     * ),
     * @OA\Response(response=401, description="Invalid credentials"),
     * @OA\Response(response=403, description="Access Denied (User not in required groups)"),
     * @OA\Response(response=422, description="Validation error")
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
            $localUser = LocalUser::updateOrCreate(
                ['username' => $adUser->getFirstAttribute('samaccountname'), 'domain' => $domain],
                [
                    'name' => $adUser->getFirstAttribute('displayname'),
                    'email' => $adUser->getFirstAttribute('mail') ?? $username.'@'.$domain, 
                    'password' => Hash::make(Str::random(40))
                ]
            );

            // 4. Create and return Sanctum token
            // The $roles array (now just strings) is passed as the token's abilities
            $token = $localUser->createToken('ad-api-token', $roles)->plainTextToken;

            return response()->json([
                'token' => $token,
                'user' => [
                    'name' => $localUser->name,
                    'email' => $localUser->email,
                    'roles' => $roles // <-- Use the raw roles array
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
     * summary="Log out user and revoke current token",
     * tags={"Authentication"},
     * security={{"sanctum":{}}},
     * @OA\Response(response=204, description="Successfully logged out"),
     * @OA\Response(response=401, description="Unauthenticated")
     * )
     */
    public function logout(Request $request): JsonResponse
    {
        $request->user()->currentAccessToken()->delete();
        return response()->json([], 204);
    }
}

