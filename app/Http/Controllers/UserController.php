<?php

namespace App\Http\Controllers;

use App\Services\AdService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Auth;
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
    * path="/api/config",
    * summary="Get configuration details",
    * description="Provides domain and optional group configuration details used for user management.",
    * tags={"Users"},
    * @OA\Response(response=200, description="Configuration retrieved successfully")
    * )
    */
    public function getConfig()
    {
        // Use the new keystone.php configuration keys
        return response()->json([
            'domains' => config('keystone.adSettings.domains', []),
            'optionalGroupsForStandard' => config('keystone.provisioning.optionalGroupsForStandardUser', []),
            'optionalGroupsForHighPrivilege' => config('keystone.provisioning.optionalGroupsForHighPrivilegeUsers', []),
        ]);
    }   

    /**
     * @OA\Get(
     * path="/api/v1/users",
     * summary="List AD users by domain",
     * tags={"Users"},
     * security={{"sanctum": {}}},
     * @OA\Parameter(name="domain", in="query", required=true, description="Domain name to filter users (e.g. ncc.lab)", @OA\Schema(type="string", example="ncc.lab")),
     * @OA\Parameter(name="name", in="query", required=false, description="Filter by display name contains", @OA\Schema(type="string", example="John")),
     * @OA\Response(response=200, description="List of users"),
     * @OA\Response(response=403, description="Unauthorized"),
     * @OA\Response(response=422, description="Validation error")
     * )
     */
    public function index(Request $request): JsonResponse
    {
        // --- Authorization ---
        $authUser = Auth::user();
        
        if (!$authUser->hasGeneralAccess && !$authUser->hasHighPrivilegeAccess) {
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
            'nameFilter' => 'nullable|string'
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $data = $validator->validated();

        $users = $this->adService->listUsers($data['domain'] ?? null,$data['nameFilter'] ?? null);

        return response()->json($users);
    }

/**
    * @OA\Post(
    * path="/api/v1/users",
    * summary="Create a new Active Directory user",
    * description="Creates a new user in the specified domain.
    * - User managers can create standard users (saved under provisioning->ouStandardUser).
    * - Admin managers can also create admin users (username ends with -a, saved under provisioning->ouPrivilegeUser).
    * - Optional groups can be assigned from configuration lists.
    * ",
    * tags={"Users"},
    *
    * @OA\RequestBody(
    * required=true,
    * @OA\JsonContent(
    * required={
    * "domain", "badge_number", "first_name", "last_name",
    * "mobile_number", "date_of_birth", "badge_expiration_date"
    * },
    * @OA\Property(property="domain", type="string", example="corp.example.com"),
    * @OA\Property(property="badge_number", type="string", example="987654"),
    * @OA\Property(property="first_name", type="string", example="Jane"),
    * @OA\Property(property="last_name", type="string", example="Smith"),
    * @OA\Property(property="mobile_number", type="string", example="+15559876543"),
    * @OA\Property(property="date_of_birth", type="string", format="date", example="1990-01-25"),
    * @OA\Property(property="badge_expiration_date", type="string", format="date", example="2026-12-31"),
    * @OA\Property(property="has_admin", type="boolean", example=false),
    * @OA\Property(
    * property="groups_standard_user",
    * type="array",
    * @OA\Items(type="string", example="CN=Finance-Users,OU=Groups,DC=corp,DC=example,DC=com")
    * ),
    * @OA\Property(
    * property="groups_privilege_user",
    * type="array",
    * @OA\Items(type="string", example="CN=Domain-Admins,OU=Groups,DC=corp,DC=example,DC=com")
    * )
    * )
    * ),
    *
    * @OA\Response(
    * response=201,
    * description="User created successfully",
    * @OA\JsonContent(
    * @OA\Property(property="message", type="string", example="User created successfully."),
    * @OA\Property(property="username", type="string", example="jsmith"),
    * @OA\Property(property="initial_password", type="string", example="TempP@ss123!"),
    * @OA\Property(property="admin_account_username", type="string", example="jsmith-admin"),
    * @OA\Property(property="admin_initial_password", type="string", example="Adm1nP@ss!")
    * )
    * ),
    *
    * @OA\Response(
    * response=403,
    * description="Unauthorized action or insufficient privileges",
    * @OA\JsonContent(
    * @OA\Property(property="message", type="string", example="Unauthorized to create admin accounts.")
    * )
    * ),
    *
    * @OA\Response(
    * response=422,
    * description="Validation failed",
    * @OA\JsonContent(
    * @OA\Property(property="errors", type="object", example={"mobile_number": {"The mobile_number field is required."}})
    * )
    * ),
    *
    * @OA\Response(
    * response=500,
    * description="Server error",
    * @OA\JsonContent(
    * @OA\Property(property="message", type="string", example="Failed to create user: LDAP connection failed")
    * )
    * ),
    *
    * security={{"bearerAuth": {}}}
    * )
    */
    public function store(Request $request): JsonResponse
    {
        $user = Auth::user();

        if (!$user->hasGeneralAccess && !$user->hasHighPrivilegeAccess) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }

        // --- Validation ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))],
            'badge_number' => ['required', 'string', 'regex:/^[0-9]+$/'],
            'first_name' => 'required|string',
            'last_name' => 'required|string',
            'mobile_number' => ['required', 'string', 'regex:/^(\+|0)[0-9]+$/'],
            'date_of_birth' => ['required', 'date_format:Y-m-d','before_or_equal:-18 years'],
            'date_of_expiry' => ['required', 'date_format:Y-m-d','after:today','after_or_equal:+3 months'],
            'has_admin' => 'boolean',
            'groups_standard_user' => 'array',
            'groups_privilege_user' => 'array',
        ]);

        $validator->sometimes('groups_privilege_user', 'required|array|min:1', function ($input) {
            return !empty($input->has_admin);
        });

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $data = $validator->validated();
        $data['has_admin'] = !empty($data['has_admin']); // Ensure boolean

        // --- Enforce Role Permissions ---
        if ($data['has_admin'] && !$user->hasHighPrivilegeAccess) {
            return response()->json(['message' => 'Unauthorized to create admin accounts.'], 403);
        }

        // --- Check if user exist ---
        if ($this->adService->findUserBySamAccountName($data['badge_number'],$data['domain'])) {
            return response()->json(['message' => 'User '.$data['badge_number'].' already exist.'], 403);
        }

        // --- Check if admin user exist ---
        if ($data['has_admin'] && $this->adService->findUserBySamAccountName($data['badge_number'].'-a',$data['domain'])) {
            return response()->json(['message' => 'Admin user '.$data['badge_number'].'-a already exist.'], 403);
        }

        // --- Provisioning Logic ---
        try {

            // --- Initialize result variables ---
            $userResult = null;
            $adminResult = null;

            // Pass auth context to service
            $data['hasGeneralAccess'] = $user->hasGeneralAccess;
            $data['hasHighPrivilegeAccess'] = $user->hasHighPrivilegeAccess;

            // --- Create Regular Account ---
            $userResult = $this->adService->createUser($data);

            // --- Create Admin Account ---
            if ($data['has_admin'] && $user->hasHighPrivilegeAccess) {
                // We already checked if it exists, so we just create
                $adminResult = $this->adService->createAdminUser($data);
            }

            $response = [
                'message' => 'User created successfully.',
                'standard_information' => [
                    'username' => $userResult['user'] ? $userResult['user']->samaccountname[0] : $data['badge_number'],
                    'password' => $userResult['password'] ?? null,
                    'groups' => $data['groups_standard_user'] ?? []
                ]
            ];

            if ($adminResult) {
                $response['admin_information'] = [
                    'username' => $adminResult['user'] ? $adminResult['user']->samaccountname[0] : $data['badge_number'].'-a',
                    'password' => $adminResult['initialPassword'] ?? null,
                    'groups'   => $data['groups_privilege_user'] ?? []
                ];
            }

            return response()->json($response, 201);

        } catch (\Exception $e) {
            \Log::error('User creation failed: ' . $e->getMessage());
            return response()->json(['message' => 'Failed to create user: ' . $e->getMessage()], 500);
        }
    }

    /**
    * @OA\Put(
    * path="/api/v1/users/{samaccountname}",
    * summary="Update user details",
    * tags={"Users"},
    *
    * @OA\Parameter(
    * name="samaccountname",
    * in="path",
    * required=true,
    * description="The user's CURRENT SAM account name (AD username). This parameter is part of the URL but the service logic will use 'badge_number' from the payload as the primary key.",
    * @OA\Schema(type="string", example="118155")
    * ),
    *
    * @OA\RequestBody(
    * required=true,
    * @OA\JsonContent(
    * required={
    * "domain", "badge_number", "first_name", "last_name",
    * "mobile_number", "date_of_birth", "date_of_expiry"
    * },
    * @OA\Property(property="domain", type="string", example="ncc.lab"),
    * @OA\Property(property="badge_number", type="string", example="123756391", description="The SAM account name of the user to update. This is the primary key for the update operation."),
    * @OA\Property(property="first_name", type="string", example="Jane"),
    * @OA\Property(property="last_name", type="string", example="Doe"),
    * @OA\Property(property="mobile_number", type="string", example="0556984261"),
    * @OA\Property(property="date_of_birth", type="string", format="date", example="1984-01-25"),
    * @OA\Property(property="date_of_expiry", type="string", format="date", example="2027-12-31"),
    * @OA\Property(property="has_admin", type="boolean", example=false, description="Set to true to create or update the associated admin account"),
    * @OA\Property(
    * property="groups_standard_user",
    * type="array",
    * @OA\Items(type="string", example="CN=RDP-EMS,CN=Users,DC=ncc,DC=lab")
    * ),
    * @OA\Property(
    * property="groups_privilege_user",
    * type="array",
    * @OA\Items(type="string", example="CN=L3,CN=Users,dc=ncc,dc=lab")
    * )
    * )
    * ),
    *
    * @OA\Response(
    * response=200,
    * description="User updated successfully",
    * @OA\JsonContent(
    * @OA\Property(property="message", type="string", example="User updated successfully.")
    * )
    * ),
    * @OA\Response(
    * response=403,
    * description="Unauthorized action",
    * @OA\JsonContent(
    * @OA\Property(property="message", type="string", example="This action is unauthorized.")
    * )
    * ),
    * @OA\Response(
    * response=404,
    * description="User not found",
    * @OA\JsonContent(
    * @OA\Property(property="message", type="string", example="User '123756391' not found in domain 'ncc.lab'.")
    * )
    * ),
    * @OA\Response(
    * response=422,
    * description="Validation failed",
    * @OA\JsonContent(
    * @OA\Property(property="errors", type="object", example={"badge_number": {"The badge_number field is required."}})
    * )
    * ),
    * @OA\Response(
    * response=500,
    * description="Server error",
    * @OA\JsonContent(
    * @OA\Property(property="message", type="string", example="Failed to update user: Unexpected error")
    * )
    * ),
    * security={{"bearerAuth": {}}}
    * )
    */
    public function update(Request $request, string $samaccountname): JsonResponse
    {
        // Use $authUser to avoid conflict with $user variable from service
        $authUser = Auth::user();

        if (!$authUser->hasGeneralAccess && !$authUser->hasHighPrivilegeAccess) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }

        // --- Validation (use snake_case, matches 'store' method) ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))],
            'badge_number' => ['required', 'string', 'regex:/^[0-9]+$/'],
            'first_name' => 'required|string',
            'last_name' => 'required|string',
            'mobile_number' => ['required', 'string', 'regex:/^(\+|0)[0-9]+$/'],
            'date_of_birth' => ['required', 'date_format:Y-m-d','before_or_equal:-18 years'],
            'date_of_expiry' => ['required', 'date_format:Y-m-d','after:today','after_or_equal:+3 months'],
            'has_admin' => 'boolean',
            'groups_standard_user' => 'array',
            'groups_privilege_user' => 'array',
        ]);

        $validator->sometimes('groups_privilege_user', 'required|array|min:1', function ($input) {
            return !empty($input->has_admin);
        });

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $data = $validator->validated();
        $data['has_admin'] = !empty($data['has_admin']); // Ensure boolean

        // --- Enforce Role Permissions ---
        if ($data['has_admin'] && !$authUser->hasHighPrivilegeAccess) {
            return response()->json(['message' => 'Unauthorized to create or update admin accounts.'], 403);
        }

        // --- BUG FIX: Removed duplicated, conflicting camelCase validation block ---

        // Pass auth context to service and the original samaccountname
        $data['hasGeneralAccess'] = $authUser->hasGeneralAccess;
        $data['hasHighPrivilegeAccess'] = $authUser->hasHighPrivilegeAccess; // <-- FIX: Was HighPrivilegeAccess
        // The $samaccountname from the URL is passed here but will be ignored by AdService->updateUser
        // in favor of $data['badge_number'] as per the new logic.
        $data['current_samaccountname'] = $samaccountname; 

        try {
            $result = $this->adService->updateUser($data);

            // --- Build detailed response ---
            $response = [
                'message' => 'User updated successfully.',
                'standard_user' => [
                    'username' => $result['user'] ? $result['user']->samaccountname[0] : null,
                ]
            ];

            $adminResult = $result['admin_result'];
            $adminResponse = [
                'status' => 'none',
                'username' => null,
            ];

            if (is_array($adminResult)) {
                if (isset($adminResult['user']) && isset($adminResult['initialPassword'])) {
                    // Case: Admin account was CREATED
                    $adminResponse['status'] = 'created';
                    $adminResponse['username'] = $adminResult['user'] ? $adminResult['user']->samaccountname[0] : $data['badge_number'].'-a';
                    $adminResponse['password'] = $adminResult['initialPassword'];
                } elseif (isset($adminResult['user'])) {
                    // Case: Admin account was UPDATED
                    $adminResponse['status'] = 'updated';
                    $adminResponse['username'] = $adminResult['user'] ? $adminResult['user']->samaccountname[0] : $data['badge_number'].'-a';
                } elseif (isset($adminResult['message'])) {
                    // Case: Admin account was DISABLED
                    $adminResponse['status'] = 'disabled';
                    $adminResponse['message'] = $adminResult['message'];
                }
            }

            $response['admin_account'] = $adminResponse;
            // --- End build detailed response ---

            return response()->json($response); // Return the new detailed response

        } catch (ModelNotFoundException $e) {
            // The service will throw this if the user from 'badge_number' isn't found
            return response()->json(['message' => $e->getMessage()], 404);
        } catch (\Exception $e) {
            \Log::error("User update failed for '{$data['badge_number']}': " . $e->getMessage());
            return response()->json(['message' => 'Failed to update user: ' . $e->getMessage()], 500);
        }
    }

    /**
     * @OA\Get(
     * path="/api/v1/users/{samaccountname}",
     * summary="Get a single user by samAccountName",
     * tags={"Users"},
     * security={{"sanctum": {}}},
     * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string", example="jdoe")),
     * @OA\Parameter(name="domain", in="query", required=true, @OA\Schema(type="string", example="ncc.lab")),
     * @OA\Response(response=200, description="User details"),
     * @OA\Response(response=404, description="User not found"),
     * @OA\Response(response=422, description="Validation error")
     * )
     */
    public function show(Request $request, string $samaccountname): JsonResponse
    {
        $user = Auth::user();

        // --- Authorization ---
        if (!$user->hasGeneralAccess && !$user->hasHighPrivilegeAccess) {
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
            // Check if it's an admin account
            $adminSam = $samaccountname . (str_ends_with($samaccountname, '-a') ? '' : '-a');
            $userDetails = $this->adService->getUserDetails($domain, $adminSam);

            if(!$userDetails) {
                return response()->json(['message' => 'User not found.'], 404);
            }
        }

        return response()->json($userDetails);
    }

    /**
     * @OA\Patch(
     * path="/api/v1/users/{samaccountname}/enable",
     * summary="Enable a user account",
     * tags={"Users"},
     * security={{"sanctum":{}}},
     * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     * @OA\RequestBody(required=true,
     * @OA\JsonContent(required={"domain"}, @OA\Property(property="domain", type="string", example="ncc.lab"))
     * ),
    * @OA\Response(response=200, description="Account enabled"),
     * @OA\Response(response=403, description="Unauthorized"),
     * @OA\Response(response=404, description="User not found"),
     * @OA\Response(response=422, description="Validation error")
     * )
     */
    public function enableAccount(Request $request, string $samaccountname): JsonResponse
    {
        // --- Authorization ---
        $user = Auth::user();

        if (!$user->hasGeneralAccess && !$user->hasHighPrivilegeAccess) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }

        // --- Validation ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))],
            'samAccountName' => ['required', 'string'],
        ]);
        
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $data = $validator->validated();
        // --- End Validation ---

        try {

            $this->adService->enableAccount($data['domain'], $samaccountname);

            if ($user->hasHighPrivilegeAccess && $this->adService->checkIfAdminAccountExists($data['domain'], $data['samAccountName'])) {
                $this->adService->setExpiration($data['domain'], $samaccountname,30);
            }

            return response()->json(['message' => 'Account(s) enabled.'], 200);

        } catch (ModelNotFoundException $e) {
            return response()->json(['message' => 'User not found.'], 404);
        }
    }

    /**
     * @OA\Patch(
     * path="/api/v1/users/{samaccountname}/disable",
     * summary="Disable a user account",
     * tags={"Users"},
     * security={{"sanctum":{}}},
     * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     * @OA\RequestBody(required=true,
     * @OA\JsonContent(required={"domain"}, @OA\Property(property="domain", type="string", example="ncc.lab"))
     * ),
     * @OA\Response(response=200, description="Account disabled"),
     * @OA\Response(response=403, description="Unauthorized"),
     * @OA\Response(response=404, description="User not found"),
     * @OA\Response(response=422, description="Validation error")
     * )
     */
    public function disableAccount(Request $request, string $samaccountname): JsonResponse
    {
        // --- Authorization ---
        $user = Auth::user();

        if (!$user->hasGeneralAccess && !$user->hasHighPrivilegeAccess) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }

        // --- Validation ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))],
            'samAccountName' => ['required', 'string'],
        ]);
        
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $data = $validator->validated();
        // --- End Validation ---

        try {
            $this->adService->disableAccount($data['domain'], $samaccountname);
            
            return response()->json(['message' => 'Account(s) disabled.'], 200);
        } catch (ModelNotFoundException $e) {
            return response()->json(['message' => 'User not found.'], 404);
        }
    }

    /**
     * @OA\Patch(
     * path="/api/v1/users/{samaccountname}/unlock",
     * summary="Unlock a user account",
     * tags={"Users"},
     * security={{"sanctum":{}}},
     * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     * @OA\RequestBody(required=true,
     * @OA\JsonContent(required={"domain"}, @OA\Property(property="domain", type="string", example="ncc.lab"))
     * ),
     * @OA\Response(response=200, description="Account unlocked"),
     * @OA\Response(response=403, description="Unauthorized"),
     * @OA\Response(response=404, description="User not found"),
     * @OA\Response(response=422, description="Validation error")
     * )
     */
    public function unlockAccount(Request $request, string $samaccountname): JsonResponse
    {
        // --- Authorization ---
        $user = Auth::user();

        if (!$user->hasGeneralAccess && !$user->hasHighPrivilegeAccess) {
            return response()->json(['message' => 'This action is unauthorized.'], 403);
        }

        // --- Validation ---
        $validator = Validator::make($request->all(), [
            'domain' => ['required', 'string', Rule::in(config('keystone.adSettings.domains', []))],
            'samAccountName' => ['required', 'string'],
        ]);
        
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $data = $validator->validated();
        // --- End Validation ---

        try {

            $this->adService->unlockAccount($data['domain'], $samaccountname);
            
            if ($user->hasHighPrivilegeAccess && $this->adService->checkIfAdminAccountExists($data['domain'], $data['samAccountName'])) {
                $this->adService->setExpiration($data['domain'], $samaccountname,30);
            }
                        
            return response()->json(['message' => 'Account(s) unlocked.'], 200);

        } catch (ModelNotFoundException $e) {
            return response()->json(['message' => 'User not found.'], 404);
        }
    }
}