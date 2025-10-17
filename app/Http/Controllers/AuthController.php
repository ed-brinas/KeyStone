<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use LdapRecord\Container;
use LdapRecord\Connection;
use LdapRecord\Models\ActiveDirectory\User;
use LdapRecord\LdapRecordException;

class AuthController extends Controller
{
    /**
     * Handle a login request to the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'domain' => 'required|string',
            'username' => 'required|string',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['message' => 'Validation failed', 'errors' => $validator->errors()], 422);
        }

        $credentials = $request->only('username', 'password');
        $domain = $request->input('domain');

        // Dynamically set up a connection for the selected domain to validate credentials
        $connection = new Connection([
            'hosts' => [env('LDAP_HOST')],
            'username' => $credentials['username'] . '@' . $domain,
            'password' => $credentials['password'],
            'base_dn' => 'dc=' . str_replace('.', ',dc=', $domain),
            'port' => env('LDAP_PORT', 389),
            'use_ssl' => env('LDAP_SSL', false),
            'use_tls' => env('LDAP_TLS', false),
        ]);

        try {
            // Attempt to bind with the user's credentials
            $connection->connect();

            // If the bind is successful, the credentials are valid.
            // We'll now use the admin credentials to find the user and log them in.
            config([
                'ldap.connections.default.hosts.0' => env('LDAP_HOST'),
                'ldap.connections.default.username' => env('LDAP_USERNAME'),
                'ldap.connections.default.password' => env('LDAP_PASSWORD'),
                'ldap.connections.default.base_dn' => 'dc=' . str_replace('.', ',dc=', $domain),
            ]);

            Auth::shouldUse('default');

            if (Auth::attempt($credentials)) {
                $request->session()->regenerate();
                Log::info('User ' . $credentials['username'] . ' successfully authenticated.');
                return response()->json(['message' => 'Login successful']);
            }

        } catch (LdapRecordException $e) {
            Log::error('LDAP bind failed for user ' . $credentials['username'] . ': ' . $e->getMessage());
            // This catches bind failures, which means invalid credentials
            return response()->json(['message' => 'Invalid credentials'], 401);
        } catch (\Exception $e) {
            Log::error('An unexpected error occurred during login for user ' . $credentials['username'] . ': ' . $e->getMessage());
            return response()->json(['message' => 'An unexpected error occurred.'], 500);
        }

        return response()->json(['message' => 'Invalid credentials'], 401);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        if (!Auth::check()) {
            return response()->json(['message' => 'User is not authenticated.'], 401);
        }

        $user = Auth::user();
        $domain = config('keystone.adSettings.forestRootDomain');
        $generalAccessGroups = config('keystone.applicationAccessControl.generalAccessGroups', []);
        $highPrivilegeGroups = config('keystone.applicationAccessControl.highPrivilegeGroups', []);

        $userGroups = $user->groups()->get()->pluck('cn')->flatten()->toArray();

        $canAccess = count(array_intersect($userGroups, $this->getGroupNames($generalAccessGroups, $domain))) > 0;
        $isHighPrivilege = count(array_intersect($userGroups, $this->getGroupNames($highPrivilegeGroups, $domain))) > 0;

        if (!$canAccess && !$isHighPrivilege) {
             return response()->json(['message' => 'Authorization Denied.'], 403);
        }

        return response()->json([
            'name' => $user->samaccountname[0],
            'isHighPrivilege' => $isHighPrivilege,
        ]);
    }

    /**
     * Log the user out of the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Helper to extract CN from DNs
     */
    private function getGroupNames(array $groupDns, string $domain): array
    {
        $names = [];
        foreach ($groupDns as $dn) {
            $fullDn = str_replace('{domain-components}', 'dc=' . str_replace('.', ',dc=', $domain), $dn);
            preg_match('/CN=([^,]+)/', $fullDn, $matches);
            if (isset($matches[1])) {
                $names[] = $matches[1];
            }
        }
        return $names;
    }
}
