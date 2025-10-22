<?php

namespace App\Http\Controllers;

use App\Services\AdService;
use Illuminate\Http\JsonResponse;

/**
 * @OA\Tag(
 * name="Health Check",
 * description="API health and connectivity endpoints."
 * )
 */
class HealthController extends Controller
{
    protected AdService $adService;

    public function __construct(AdService $adService)
    {
        $this->adService = $adService;
    }

    /**
     * @OA\Get(
     * path="/api/v1/health",
     * summary="Check API and AD connectivity",
     * tags={"Health Check"},
     * @OA\Response(
     * response=200,
     * description="Connectivity status",
     * @OA\JsonContent(
     * properties={
     * @OA\Property(property="api_status", type="string", example="online"),
     * @OA\Property(property="ad_connectivity", type="object")
     * }
     * )
     * )
     * )
     */
    public function check(): JsonResponse
    {
        $adStatus = $this->adService->checkAdConnectivity();
        $hasError = false;

        foreach ($adStatus as $status) {
            if (is_array($status) && $status['status'] === 'error') {
                $hasError = true;
                break;
            }
        }

        return response()->json([
            'api_status' => 'online',
            'ad_connectivity' => $adStatus
        ], $hasError ? 503 : 200); // 503 Service Unavailable if any domain fails
    }
}

