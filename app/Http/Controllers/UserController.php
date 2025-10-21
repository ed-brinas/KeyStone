<?php

namespace App\Http\Controllers;

use App\Http\Requests\CreateUserRequest;
use App\Http\Requests\UpdateUserRequest;
use App\Services\AdService;
use Illuminate\Http\JsonResponse;
use LdapRecord\Models\ActiveDirectory\User as AdUser;

class UserController extends Controller
{
    protected AdService $adService;

    public function __construct(AdService $adService)
    {
        $this->adService = $adService;
    }

    /**
     * @OA\Post(
     * path="/api/v1/users",
     * summary="Create a new Active Directory user",
     * tags={"User Management"},
     * security={{"sanctum":{}}},
     * @OA\RequestBody(
     * required=true,
     * description="User creation data",
     * @OA\JsonContent(ref="#/components/schemas/CreateUserRequest")
     * ),
     * @OA\Response(response=201, description="User created successfully"),
     * @OA\Response(response=422, description="Validation error")
     * )
     */
    public function store(CreateUserRequest $request): JsonResponse
    {
        $user = $this->adService->createUser($request->validated());
        
        $password = $this->adService->generatePassword();
        $this->adService->resetPassword($user, $password);

        return response()->json([
            'message' => 'User created successfully.',
            'username' => $user->getSamAccountName(),
            'initial_password' => $password
        ], 201);
    }

    /**
     * @OA\Get(
     * path="/api/v1/users/{samaccountname}",
     * summary="Get user details",
     * tags={"User Management"},
     * security={{"sanctum":{}}},
     * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     * @OA\Response(response=200, description="User details"),
     * @OA\Response(response=404, description="User not found")
     * )
     */
    public function show(string $samaccountname): JsonResponse
    {
        // Note: Domain context must be set before this call, ideally via middleware
        $user = $this->adService->findUserByUsername($samaccountname);

        if (!$user) {
            return response()->json(['message' => 'User not found.'], 404);
        }

        return response()->json([
            'username' => $user->getSamAccountName(),
            'display_name' => $user->getDisplayName(),
            'email' => $user->getEmail(),
            'first_name' => $user->getFirstName(),
            'last_name' => $user->getLastName(),
            'enabled' => !$user->isDisabled(),
            'locked' => $user->isLockedout(),
        ]);
    }
    
    /**
     * @OA\Patch(
     * path="/api/v1/users/{samaccountname}/enable",
     * summary="Enable a user account",
     * tags={"User Management"},
     * security={{"sanctum":{}}},
     * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     * @OA\Response(response=204, description="Account enabled"),
     * @OA\Response(response=404, description="User not found")
     * )
     */
    public function enable(string $samaccountname): JsonResponse
    {
        $user = $this->adService->findUserByUsername($samaccountname);
        if (!$user) {
            return response()->json(['message' => 'User not found.'], 404);
        }
        $this->adService->enableAccount($user);
        return response()->json([], 204);
    }

    /**
     * @OA\Patch(
     * path="/api/v1/users/{samaccountname}/disable",
     * summary="Disable a user account",
     * tags={"User Management"},
     * security={{"sanctum":{}}},
     * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     * @OA\Response(response=204, description="Account disabled"),
     * @OA\Response(response=404, description="User not found")
     * )
     */
    public function disable(string $samaccountname): JsonResponse
    {
        $user = $this->adService->findUserByUsername($samaccountname);
        if (!$user) {
            return response()->json(['message' => 'User not found.'], 404);
        }
        $this->adService->disableAccount($user);
        return response()->json([], 204);
    }

    /**
     * @OA\Patch(
     * path="/api/v1/users/{samaccountname}/unlock",
     * summary="Unlock a user account",
     * tags={"User Management"},
     * security={{"sanctum":{}}},
     * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     * @OA\Response(response=204, description="Account unlocked"),
     * @OA\Response(response=404, description="User not found")
     * )
     */
    public function unlock(string $samaccountname): JsonResponse
    {
        $user = $this->adService->findUserByUsername($samaccountname);
        if (!$user) {
            return response()->json(['message' => 'User not found.'], 404);
        }
        $this->adService->unlockAccount($user);
        return response()->json([], 204);
    }
}
