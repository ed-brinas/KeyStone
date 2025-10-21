<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

/**
 * @OA\Schema(
 * schema="CreateUserRequest",
 * title="Create User Request",
 * required={"firstName", "lastName", "samaccountname", "domain"},
 * @OA\Property(
 * property="firstName",
 * type="string",
 * description="The user's first name.",
 * example="John"
 * ),
 * @OA\Property(
 * property="lastName",
 * type="string",
 * description="The user's last name.",
 * example="Doe"
 * ),
 * @OA\Property(
 * property="samaccountname",
 * type="string",
 * description="The desired username (SAM account name).",
 * example="jdoe"
 * ),
 * @OA\Property(
 * property="domain",
 * type="string",
 * description="The target Active Directory domain.",
 * example="ncc.local"
 * ),
 * @OA\Property(
 * property="isPrivileged",
 * type="boolean",
 * description="Set to true to create a privileged '-a' account.",
 * example=false
 * ),
 * @OA\Property(
 * property="optionalGroups",
 * type="array",
 * @OA\Items(type="string"),
 * description="A list of optional security groups to add the user to.",
 * example={"CN=L1,CN=Users,DC=ncc,DC=local"}
 * )
 * )
 */
class CreateUserRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     * Authorization is handled by middleware, so we return true.
     *
     * @return bool
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        // Get the list of valid domains from the keystone config
        $validDomains = config('keystone.adSettings.domains', []);

        return [
            'firstName' => 'required|string|max:255',
            'lastName' => 'required|string|max:255',
            'samaccountname' => 'required|string|max:20|regex:/^[a-zA-Z0-9._-]+$/',
            'domain' => ['required', 'string', Rule::in($validDomains)],
            'isPrivileged' => 'sometimes|boolean',
            'optionalGroups' => 'sometimes|array',
            'optionalGroups.*' => 'string', // Validate each item in the array is a string
        ];
    }
}
