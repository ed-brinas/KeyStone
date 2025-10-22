<?php

namespace App\Http\Controllers;

use App\Services\AdService;
use Illuminate\Http\JsonResponse;
use LdapRecord\Models\ModelNotFoundException;
use Illuminate\Http\Request; // <-- Use standard request
use Illuminate\Support\Facades\Validator; // <-- For manual validation
use Illuminate\Validation\Rule; // <-- For domain rule
use Illuminate\Support\Facades\Auth; // <-- For auth checks

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
     * summary="Reset a standard user's password",
     * tags={"Password Management"},
     * security={{"sanctum":{}}},
     * @OA\RequestBody(
     * required=true,
     * description="User identification",
     * @OA\JsonContent(ref="#/components/schemas/ResetStandardPasswordRequest")
     * ),
     * @OA\Response(
     * response=200,
     * description="Password reset successfully",
     * @OA\JsonContent(
     * @OA\Property(property="message", type="string", example="Password reset successfully."),
     * @OA\Property(property="initial_password", type="string", example="nEw!P@ssw0rd")
     * )
     * ),
     * @OA\Response(response=403, description="Unauthorized"),
     * @OA\Response(response=404, description="User not found")
     * )
     */
    public function resetStandardPassword(Request $request): JsonResponse
    {
        // --- Authorization ---
        if (!Auth::user()->tokenCan('l2') && !Auth::user()->tokenCan('l3') && !Auth::user()->tokenCan('domain admins')) {
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
                'initial_password' => $password
            ]);
        } catch (ModelNotFoundException $e) {
            return response()->json(['message' => 'User not found.'], 404);
        } catch (\Exception $e) {
            return response()->json(['message' => 'Failed to reset password: ' . $e->getMessage()], 500);
        }
    }

    /**
     * @OA\Post(
     * path="/api/v1/passwords/reset-admin",
     * summary="Reset a privileged user's (-a) password",
     * tags={"Password Management"},
     * security={{"sanctum":{}}},
     * @OA\RequestBody(
     * required=true,
     * description="Base user identification",
     * @OA\JsonContent(ref="#/components/schemas/ResetAdminPasswordRequest")
     * ),
     * @OA\Response(
     * response=200,
     * description="Password reset successfully",
     * @OA\JsonContent(
     * @OA\Property(property="message", type="string", example="Password reset successfully."),
     * @OA\Property(property="initial_password", type="string", example="nEw!P@ssw0rd")
     * )
     * ),
     * @OA\Response(response=403, description="Unauthorized"),
     * @OA\Response(response=404, description="Admin user not found")
     * )
     */
    public function resetAdminPassword(Request $request): JsonResponse
    {
        // --- Authorization ---
        if (!Auth::user()->tokenCan('l3') && !Auth::user()->tokenCan('domain admins')) {
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
            $password = $this->adService->resetAdminPassword($data['domain'], $data['samAccountName']);

            return response()->json([
                'message' => 'Admin password reset successfully.',
                'initial_password' => $password
            ]);
        } catch (ModelNotFoundException $e) {
            return response()->json(['message' => 'Admin user not found.'], 404);
        } catch (\Exception $e) {
            return response()->json(['message' => 'Failed to reset admin password: ' . $e->getMessage()], 500);
        }
    }
}

