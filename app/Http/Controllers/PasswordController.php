<?php

namespace App\Http\Controllers;

use App\Services\AdService;
use Illuminate\Http\JsonResponse;
use LdapRecord\Models\ModelNotFoundException;
use Illuminate\Http\Request; // <-- Use standard request
use Illuminate\Support\Facades\Validator; // <-- For manual validation
use Illuminate\Validation\Rule; // <-- For domain rule
use Illuminate\Support\Facades\Auth; // <-- For auth checks

/**
* @OA\Schema(
* schema="ResetStandardPasswordRequest",
* type="object",
* required={"username", "new_password"},
* @OA\Property(property="username", type="string", example="jdoe", description="The username whose password should be reset"),
* @OA\Property(property="new_password", type="string", example="NewSecureP@ssw0rd", description="The new password to set for the user")
* )
*
* @OA\Schema(
* schema="ResetAdminPasswordRequest",
* type="object",
* required={"admin_username", "target_username", "new_password"},
* @OA\Property(property="admin_username", type="string", example="admin.user", description="The admin performing the reset"),
* @OA\Property(property="target_username", type="string", example="jdoe", description="The username whose password is being reset"),
* @OA\Property(property="new_password", type="string", example="StrongAdminP@ss!23", description="The new password to assign to the user")
* )
*/
class PasswordController extends Controller
{
    protected AdService $adService;

    public function __construct(AdService $adService)
    {
        $this->adService = $adService;
    }

    /**
    * @OA\Post(
    * path="/api/v1/passwords/reset-standard",
    * summary="Reset a standard user password",
    * tags={"Password Management"},
    * security={{"bearerAuth": {}}},
    * @OA\RequestBody(
    * required=true,
    * @OA\JsonContent(ref="#/components/schemas/ResetStandardPasswordRequest")
    * ),
    * @OA\Response(response=200, description="Password reset successful"),
    * @OA\Response(response=400, description="Invalid input or password policy violation"),
    * @OA\Response(response=401, description="Unauthorized")
    * )
    */
    public function resetPassword(Request $request): JsonResponse
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

            $user = $this->adService->findUserBySamAccountName($data['samAccountName'], $data['domain']);

            if (!$user) {
                return response()->json(['message' => 'User not found.'], 404);
            }

            $password = $this->adService->generatePassword();
            $this->adService->resetPassword($user, $password, true); // Force change on next login

            return response()->json([
                'message' => 'Password reset successfully.',
                'newPassword' => $password
            ]);
            
        } catch (ModelNotFoundException $e) {
            return response()->json(['message' => 'User not found.'], 404);
        } catch (\Exception $e) {
            return response()->json(['message' => 'Failed to reset password: ' . $e->getMessage()], 500);
        }
    }
}

