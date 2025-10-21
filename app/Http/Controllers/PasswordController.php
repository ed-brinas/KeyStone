<?php

namespace App\Http\Controllers;

use App\Services\AdService;
use Illuminate\Http\JsonResponse;
use LdapRecord\Models\ActiveDirectory\User as AdUser;

class PasswordController extends Controller
{
    protected AdService $adService;

    public function __construct(AdService $adService)
    {
        $this->adService = $adService;
    }

    /**
     * @OA\Post(
     * path="/api/v1/users/{samaccountname}/reset-password",
     * summary="Reset a standard user's password",
     * tags={"Password Management"},
     * security={{"sanctum":{}}},
     * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string")),
     * @OA\Response(
     * response=200,
     * description="Password has been reset",
     * @OA\JsonContent(
     * @OA\Property(property="new_password", type="string")
     * )
     * ),
     * @OA\Response(response=404, description="User not found")
     * )
     */
    public function resetStandardPassword(string $samaccountname): JsonResponse
    {
        $user = $this->adService->findUserByUsername($samaccountname);

        if (!$user) {
            return response()->json(['message' => 'User not found.'], 404);
        }

        $newPassword = $this->adService->generatePassword();
        $this->adService->resetPassword($user, $newPassword);

        return response()->json(['new_password' => $newPassword]);
    }

    /**
     * @OA\Post(
     * path="/api/v1/users/{samaccountname}/reset-admin-password",
     * summary="Reset a privileged admin user's password",
     * tags={"Password Management"},
     * security={{"sanctum":{}}},
     * @OA\Parameter(name="samaccountname", in="path", required=true, @OA\Schema(type="string", description="The base username, e.g., 'jdoe' not 'jdoe-a'")),
     * @OA\Response(
     * response=200,
     * description="Admin password has been reset",
     * @OA\JsonContent(
     * @OA\Property(property="new_password", type="string")
     * )
     * ),
     * @OA\Response(response=404, description="Admin account not found")
     * )
     */
    public function resetAdminPassword(string $samaccountname): JsonResponse
    {
        $adminUsername = $samaccountname . '-a';
        $adminUser = $this->adService->findUserByUsername($adminUsername);

        if (!$adminUser) {
            return response()->json(['message' => 'Admin account not found.'], 404);
        }

        $newPassword = $this->adService->generatePassword();
        $this->adService->resetPassword($adminUser, $newPassword);

        return response()->json(['new_password' => $newPassword]);
    }
}
