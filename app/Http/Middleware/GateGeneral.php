<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use LdapRecord\Models\ActiveDirectory\Group;

class GateGeneral
{
    public function handle(Request $request, Closure $next)
    {
        $user = Auth::user(); // LdapRecord AD user model
        $allowed = false;

        foreach (config('adsettings.groups.general') as $groupDn) {
            if ($group = Group::find($groupDn)) {
                if ($group->members()->exists($user)) {
                    $allowed = true; break;
                }
            }
        }

        abort_if(!$allowed, 403, 'Access denied');
        return $next($request);
    }
}
