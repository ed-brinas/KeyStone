<?php

namespace App\Http\Controllers;

// use App\Http\Requests\CreateUserRequest; // No longer used
// use App\Http\Requests\UpdateUserRequest; // No longer used
use App\Services\AdService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request; // <-- Use standard request
use Illuminate\Support\Facades\Validator; // <-- For manual validation
use Illuminate\Validation\Rule; // <-- For domain rule
use Illuminate\Support\Facades\Auth; // <-- For auth checks
use LdapRecord\Models\ActiveDirectory\User as AdUser;
use LdapRecord\Models\ModelNotFoundException;

/**
* @OA\Tag(name="User Management", description="Manage users across AD domains.")
*/
class UserController extends Controller
{
    protected AdService $adService;

    public function __construct(AdService $adService)
    {
        $this->adService = $adService;
    }

    /**
     * @OA\Get(
     *   path="/api/v1/users",
     *   summary="List AD users by domain",
     *   tags={"Users"},
     *   security={{"sanctum": {}}},
     *   @OA\Parameter(name="domain", in="query", required=true, description="Domain name to filter users (e.g. ncc.lab)", @OA\Schema(type="string", example="ncc.lab")),
     *   @OA\Parameter(name="name", in="query", required=false, description="Filter by display name contains", @OA\Schema(type="string", example="John")),
     *   @OA\Parameter(name="status", in="query", required=false, description="Enabled status filter", @OA\Schema(type="boolean", example=true)),
     *   @OA\Parameter(name="admin", in="query", required=false, description="Has admin account filter", @OA\Schema(type="boolean", example=false)),
     *   @OA\Response(response=200, description="List of users"),
     *   @OA\Response(response=403, description="Unauthorized"),
     *   @OA\Response(response=422, description="Validation error")
     * )
     */
    public function index(Request $request): JsonResponse
    {
        // --- Authorization ---
        if (!Auth::user()->tokenCan('l2') && !Auth::user()->tokenCan('l3') && !Auth::user()->tokenCan('domain admins')) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }
        
        // --- Normalize boolean query parameters ---
        $request->merge([
            'status' => filter_var($request->query('status'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE),
            'admin'  => filter_var($request->query('admin'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE),
        ]);

        // --- Validation ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))],
            'name' => 'nullable|string',
            'status' => 'nullable|boolean',
            'admin' => 'nullable|boolean',
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $data = $validator->validated();

        $users = $this->adService->listUsers(
            $data['domain'],
            $data['name'] ?? null,
            isset($data['status']) ? (bool)$data['status'] : null,
            isset($data['admin']) ? (bool)$data['admin'] : null
        );

        return response()->json($users);
    }

    /**
     * @OA\Post(
     *   path="/api/v1/users",
     *   summary="Create a new Active Directory user",
     *   tags={"Users"},
     *   security={{"sanctum":{}}},
     *   @OA\RequestBody(
     *     required=true,
     *     description="User creation data",
     *     @OA\JsonContent(
     *       required={"domain","samAccountName","firstName","lastName"},
     *       @OA\Property(property="domain", type="string", example="ncc.lab"),
     *       @OA\Property(property="samAccountName", type="string", example="jdoe"),
     *       @OA\Property(property="firstName", type="string", example="John"),
     *       @OA\Property(property="lastName", type="string", example="Doe"),
     *       @OA\Property(property="dateOfBirth", type="string", format="date", example="1990-05-15"),
     *       @OA\Property(property="mobileNumber", type="string", example="+966501234567"),
     *       @OA\Property(property="createAdminAccount", type="boolean", example=false),
     *       @OA\Property(property="optionalGroupsForStandardUser", type="array", @OA\Items(type="string")),
     *       @OA\Property(property="optionalGroupsForHighPrivilegeUsers", type="array", @OA\Items(type="string"))
     *     )
     *   ),
     *   @OA\Response(response=201, description="User created successfully"),
     *   @OA\Response(response=403, description="Unauthorized"),
     *   @OA\Response(response=422, description="Validation error")
     * )
     */
    public function store(Request $request): JsonResponse
    {
        // --- Authorization ---
        if (!Auth::user()->tokenCan('l3') && !Auth::user()->tokenCan('domain admins')) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }

        // --- Validation ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))],
            'samAccountName' => ['required', 'string', 'max:20', 'regex:/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/'],
            'firstName' => ['required', 'string', 'max:50'],
            'lastName' => ['required', 'string', 'max:50'],
            'dateOfBirth' => ['required', 'date_format:Y-m-d'],
            'mobileNumber' => ['required', 'string', 'max:20'],
            'createAdminAccount' => ['sometimes', 'boolean'],
            'optionalGroupsForStandardUser' => ['sometimes', 'array'],
            'optionalGroupsForStandardUser.*' => ['string'],
            'optionalGroupsForHighPrivilegeUsers' => ['sometimes', 'array'],
            'optionalGroupsForHighPrivilegeUsers.*' => ['string'],
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $data = $validator->validated();
        // --- End Validation ---

        try {
            $result = $this->adService->createUser($data);

            $response = [
                'message' => 'User created successfully.',
                'username' => $result['user']->getFirstAttribute('samaccountname'),
                'initial_password' => $result['password']
            ];

            if (isset($result['adminAccount']) && !empty($result['adminAccount'])) {
                $response['admin_account_username'] = $result['adminAccount']['user']->getFirstAttribute('samaccountname');
                $response['admin_initial_password'] = $result['adminAccount']['initialPassword'];
            }

            return response()->json($response, 201);
        } catch (\Exception $e) {
            return response()->json(['message' => 'Failed to create user: ' . $e->getMessage()], 500);
        }
    }

    /**
     * @OA\Get(
     *   path="/api/v1/users/{samaccountname}",
     *   summary="Get a single user by samAccountName",
     *   tags={"Users"},
     *   security={{"sanctum": {}}},
     *   @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string", example="jdoe")),
     *   @OA\Parameter(name="domain", in="query", required=true, @OA\Schema(type="string", example="ncc.lab")),
     *   @OA\Response(response=200, description="User details"),
     *   @OA\Response(response=404, description="User not found"),
     *   @OA\Response(response=422, description="Validation error")
     * )
     */
    public function show(Request $request, string $samaccountname): JsonResponse
    {
        // --- Authorization ---
        if (!Auth::user()->tokenCan('l2') && !Auth::user()->tokenCan('l3') && !Auth::user()->tokenCan('domain admins')) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }

        // --- Validation ---
        $validator = Validator::make($request->query(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))]
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $domain = $validator->validated()['domain'];
        // --- End Validation ---

        $userDetails = $this->adService->getUserDetails($domain, $samaccountname);

        if (!$userDetails) {
            return response()->json(['message' => 'User not found.'], 404);
        }

        return response()->json($userDetails);
    }

    /**
    * @OA\Put(
    * path="/api/v1/users/{samaccountname}",
    * summary="Update user details",
    * tags={"Users"},
    * security={{"sanctum": {}}},
    * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
    * @OA\RequestBody(required=true, description="User update data",
    * @OA\JsonContent(
    *       required={"domain","samAccountName","firstName","lastName"},
    *       @OA\Property(property="domain", type="string", example="ncc.lab"),
    *       @OA\Property(property="samAccountName", type="string", example="jdoe"),
    *       @OA\Property(property="firstName", type="string", example="John"),
    *       @OA\Property(property="lastName", type="string", example="Doe"),
    *       @OA\Property(property="dateOfBirth", type="string", format="date", example="1990-05-15"),
    *       @OA\Property(property="mobileNumber", type="string", example="+966501234567"),
    *       @OA\Property(property="createAdminAccount", type="boolean", example=false),
    *       @OA\Property(property="optionalGroupsForStandardUser", type="array", @OA\Items(type="string")),
    *       @OA\Property(property="optionalGroupsForHighPrivilegeUsers", type="array", @OA\Items(type="string"))
    * )
    * ),
    * @OA\Response(response=200, description="User updated"),
    * @OA\Response(response=403, description="Unauthorized"),
    * @OA\Response(response=404, description="User not found"),
    * @OA\Response(response=422, description="Validation error")
    * )
    */
    public function update(Request $request, string $samaccountname): JsonResponse
    {
        // --- Authorization ---
        $user = Auth::user();
        if (!$user->tokenCan('l2') && !$user->tokenCan('l3') && !$user->tokenCan('domain admins')) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }

        // If 'hasAdminAccount' is being modified, must have high-privilege
        if ($request->has('hasAdminAccount') && !$user->tokenCan('l3') && !$user->tokenCan('domain admins')) {
            return response()->json(['message' => 'Unauthorized to manage admin accounts.'], 403);
        }
        // --- End Authorization ---

        // --- Validation ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))],
            'samAccountName' => ['required', 'string', 'max:20', 'regex:/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/'],
            'firstName' => ['required', 'string', 'max:50'],
            'lastName' => ['required', 'string', 'max:50'],
            'dateOfBirth' => ['required', 'date_format:Y-m-d'],
            'mobileNumber' => ['required', 'string', 'max:20'],
            'createAdminAccount' => ['sometimes', 'boolean'],
            'optionalGroupsForStandardUser' => ['sometimes', 'array'],
            'optionalGroupsForStandardUser.*' => ['string'],
            'optionalGroupsForHighPrivilegeUsers' => ['sometimes', 'array'],
            'optionalGroupsForHighPrivilegeUsers.*' => ['string'],
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $data = $validator->validated();
        $domain = $data['domain'];
        unset($data['domain']);        
        // --- End Validation ---

        try {
            $user = $this->adService->updateUser($domain, $samaccountname, $data);
            return response()->json(['message' => 'User updated successfully.']);
        } catch (ModelNotFoundException $e) {
            return response()->json(['message' => 'User not found.'], 404);
        } catch (\Exception $e) {
            return response()->json(['message' => 'Failed to update user: ' . $e->getMessage()], 500);
        }
    }
    
    /**
     * @OA\Patch(
     *   path="/api/v1/users/{samaccountname}/enable",
     *   summary="Enable a user account",
     *   tags={"Users"},
     *   security={{"sanctum":{}}},
     *   @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true,
     *     @OA\JsonContent(required={"domain"}, @OA\Property(property="domain", type="string", example="ncc.lab"))
     *   ),
    *    @OA\Response(response=200, description="Account enabled"),
     *   @OA\Response(response=403, description="Unauthorized"),
     *   @OA\Response(response=404, description="User not found"),
     *   @OA\Response(response=422, description="Validation error")
     * )
     */
    public function enableAccount(Request $request, string $samaccountname): JsonResponse
    {
        // --- Authorization ---
        if (!Auth::user()->tokenCan('l2') && !Auth::user()->tokenCan('l3') && !Auth::user()->tokenCan('domain admins')) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }
        // --- Validation ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))]
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $domain = $validator->validated()['domain'];
        // --- End Validation ---

        try {
            $this->adService->enableAccount($domain, $samaccountname);
            return response()->json([], 204);
        } catch (ModelNotFoundException $e) {
            return response()->json(['message' => 'User not found.'], 404);
        }
    }

    /**
     * @OA\Patch(
     *   path="/api/v1/users/{samaccountname}/disable",
     *   summary="Disable a user account",
     *   tags={"Users"},
     *   security={{"sanctum":{}}},
     *   @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true,
     *     @OA\JsonContent(required={"domain"}, @OA\Property(property="domain", type="string", example="ncc.lab"))
     *   ),
     *   @OA\Response(response=200, description="Account disabled"),
     *   @OA\Response(response=403, description="Unauthorized"),
     *   @OA\Response(response=404, description="User not found"),
     *   @OA\Response(response=422, description="Validation error")
     * )
     */    
    public function disableAccount(Request $request, string $samaccountname): JsonResponse
    {
        // --- Authorization ---
        if (!Auth::user()->tokenCan('l2') && !Auth::user()->tokenCan('l3') && !Auth::user()->tokenCan('domain admins')) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }
        // --- Validation ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))]
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $domain = $validator->validated()['domain'];
        // --- End Validation ---

        try {
            $this->adService->disableAccount($domain, $samaccountname);
            return response()->json([], 204);
        } catch (ModelNotFoundException $e) {
            return response()->json(['message' => 'User not found.'], 404);
        }
    }

    /**
     * @OA\Patch(
     *   path="/api/v1/users/{samaccountname}/unlock",
     *   summary="Unlock a user account",
     *   tags={"Users"},
     *   security={{"sanctum":{}}},
     *   @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true,
     *     @OA\JsonContent(required={"domain"}, @OA\Property(property="domain", type="string", example="ncc.lab"))
     *   ),
     *   @OA\Response(response=200, description="Account unlocked"),
     *   @OA\Response(response=403, description="Unauthorized"),
     *   @OA\Response(response=404, description="User not found"),
     *   @OA\Response(response=422, description="Validation error")
     * )
     */
    public function unlockAccount(Request $request, string $samaccountname): JsonResponse
    {
        // --- Authorization ---
        if (!Auth::user()->tokenCan('l2') && !Auth::user()->tokenCan('l3') && !Auth::user()->tokenCan('domain admins')) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }
        // --- Validation ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))]
        ]);
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $domain = $validator->validated()['domain'];
        // --- End Validation ---

        try {
            $this->adService->unlockAccount($domain, $samaccountname);
            return response()->json([], 204);
        } catch (ModelNotFoundException $e) {
            return response()->json(['message' => 'User not found.'], 404);
        }
    }
}

