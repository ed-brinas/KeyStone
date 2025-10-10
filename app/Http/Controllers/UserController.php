<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Session;
use App\Models\User; // Assuming there is a User model for AD user management
use Exception;

class UserController extends Controller
{
    // Existing methods remain intact...

    /**
     * Reset a user's password and unlock the account.
     *
     * @param string $guid
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    // MODIFIED START - Added new Reset Password backend endpoint [2025-10-11 16:45]
    public function resetPassword($guid, Request $request)
    {
        try {
            // Locate user by GUID
            $user = User::where('objectguid', $guid)->first();

            if (!$user) {
                return response()->json(['success' => false, 'message' => 'User not found.'], 404);
            }

            // Generate a new secure password
            $newPassword = $this->generateStrongPassword();

            // Reset password (example AD logic or Laravel user update)
            $user->setPassword($newPassword); // Replace with actual AD or LDAP handler
            $user->unlockAccount(); // Unlock if applicable

            // Optionally mark password must change on next login
            $user->forcePasswordChange();

            Log::info('Password reset for user', ['guid' => $guid, 'username' => $user->samaccountname]);

            return response()->json([
                'success' => true,
                'username' => $user->samaccountname,
                'new_password' => $newPassword
            ]);
        } catch (Exception $e) {
            Log::error('Password reset failed: ' . $e->getMessage(), ['guid' => $guid]);
            return response()->json(['success' => false, 'message' => 'Error resetting password.'], 500);
        }
    }

    /**
     * Helper method to generate a strong random password.
     */
    private function generateStrongPassword($length = 12)
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=';
        $password = '';
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return $password;
    }
    // MODIFIED END
}
