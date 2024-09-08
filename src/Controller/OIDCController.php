<?php

namespace Erikwegner\Oidcproxy\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mime\Part\Multipart\FormDataPart;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class OIDCController extends AbstractController
{
    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly HttpClientInterface $httpClient
    ) {
    }

    /**
     * @Route("/_oidc/login", name="ewop_oidc_login", methods={"GET"})
     */
    public function login(Request $request)
    {
        $app_uri = $request->query->get("app_uri");
        $redirect_uri = $request->query->get("redirect_uri");
        $scope = $request->query->get("scope");
        // TODO: check app_uri against allowed app_uris

        $state = $this->generateRandomString(20);
        $request->getSession()->set("state", $state);
        $request->getSession()->set("app_uri", $app_uri);
        $request->getSession()->set("redirect_uri", $redirect_uri);
        // TODO: pkce

        $authUrl = $_SERVER["EWOP_AUTH_URL"];
        $clientId = $_SERVER["EWOP_CLIENT_ID"];
        if (empty($scope)) {
            $scope = "openid profile email";
        }

        $params = [
            "response_type" => "code",
            "client_id" => $clientId,
            "redirect_uri" => $redirect_uri,
            "scope" => $scope,
            "state" => $request->getSession()->get("state"),
            // TODO: pkce, nonce, code_challenge, code_challenge_method
            "promp" => "login",
            "ui_locales" => "de",
        ];

        $url = $authUrl . "?" . http_build_query($params);
        return new RedirectResponse($url);
    }

    /**
     * @Route("/_oidc/callback", name="ewop_oidc_callback", methods={"GET"})
     */
    public function callback(Request $request)
    {
        $code = $request->query->get("code");
        $tokenUrl = $_SERVER["EWOP_TOKEN_URL"];

        $clientId = $_SERVER["EWOP_CLIENT_ID"];
        $clientSecret = $_SERVER["EWOP_CLIENT_SECRET"];
        $redirectUri = $request->getSession()->get("redirect_uri");
        $app_uri = $request->getSession()->get("app_uri");

        // Prepare app_uri for additional query parameter. If it contains '?', append a '&'.
        // Otherwise, append a '?'
        $app_uri =
            strpos($app_uri, "?") === false ? $app_uri . "?" : $app_uri . "&";

        $response = $this->httpClient->request("POST", $tokenUrl, [
            "body" => [
                "grant_type" => "authorization_code",
                "client_id" => $clientId,
                "client_secret" => $clientSecret,
                "redirect_uri" => $redirectUri,
                "code" => $code,
            ],
        ]);

        if ($response->getStatusCode() >= 400) {
            $this->logger->error(
                "Failed to fetch token: " . $response->getContent()
            );
            return new RedirectResponse($app_uri . "error=login_failed");
        }

        $data = json_decode($response->getContent(), true);
        $this->tokenResponseToSession($request->getSession(), $data);

        return new RedirectResponse($app_uri . "success=1");
    }

    /**
     * @Route("/_oidc/status", name="ewop_oidc_status", methods={"GET"})
     */
    public function status(Request $request)
    {
        $this->checkAndRefreshToken($request->getSession());

        // remaining seconds until access token expires
        $accessTokenExpiresAt = $request
            ->getSession()
            ->get("ewop_token_expires_at");
        $remainingSeconds = max(0, $accessTokenExpiresAt - time());

        // remaining seconds until refresh token expires
        $refreshTokenExpiresAt = $request
            ->getSession()
            ->get("ewop_refresh_token_expires_at");
        $remainingSecondsRefresh = max(0, $refreshTokenExpiresAt - time());

        return new JsonResponse([
            "status" => $remainingSeconds + $remainingSecondsRefresh > 0,
            "expires_in" => $remainingSeconds,
            "refresh_expires_in" => $remainingSecondsRefresh,
        ]);
    }

    /**
     * @Route(
     *       "/_oidcp/{api}/{path}",
     *       name="ewop_oidc_proxy",
     *       requirements={"api"="[a-z]+","path"=".+"},
     *       methods={"GET", "POST", "PUT", "PATCH", "DELETE"}
     * )
     */
    public function proxy(Request $request, $api, $path)
    {
        $jwt = $request->getSession()->get("ewop_access_token");
        if (!$jwt || !$this->checkAndRefreshToken($request->getSession())) {
            return new Response("Unauthorized", 401);
        }

        $url = $_SERVER["EWOP_API_" . strtoupper($api) . "_URL"];
        if (empty($url)) {
            return new Response("Invalid request", 400);
        }

        $url = $url . $path;
        $method = $request->getMethod();
        $headers = array_merge($request->headers->all(), [
            "Authorization" => "Bearer " . $jwt,
        ]);

        $options = [
            "headers" => $headers,
            "query" => $request->query->all(),
        ];

        if (in_array($method, ['POST', 'PUT', 'PATCH'])) {
            if (strpos($request->headers->get('Content-Type'), 'multipart/form-data') !== false) {

                $boundary = '----WebKitFormBoundary' . md5(time()); // Erstelle einen Boundary-String
                $options['headers']['Content-Type'] = 'multipart/form-data; boundary=' . $boundary;
                $body = '';

                // Add files
                foreach ($request->files as $fileKey => $file) {
                    if ($file->isValid()) {
                        $body .= "--" . $boundary . "\r\n";
                        $body .= 'Content-Disposition: form-data; name="' . $fileKey . '"; filename="' . $file->getClientOriginalName() . '"' . "\r\n";
                        $body .= 'Content-Type: ' . $file->getClientMimeType() . "\r\n\r\n";
                        $body .= file_get_contents($file->getPathname()) . "\r\n";
                    }
                }

                // Add form fields
                foreach ($request->request->all() as $key => $value) {
                    $body .= "--" . $boundary . "\r\n";
                    $body .= 'Content-Disposition: form-data; name="' . $key . '"' . "\r\n\r\n";
                    $body .= $value . "\r\n";
                }

                $body .= "--" . $boundary . "--\r\n"; // Abschluss der Multipart-Daten

                $options['body'] = $body;
            } else {
                // Standard-POST/PUT/PATCH-Daten
                $options['body'] = $request->getContent();
            }
        }

        $this->logger->notice("options", $options);

        $response = $this->httpClient->request($method, $url, $options);

        $statusCode = $response->getStatusCode();

        return new Response(
            $response->getContent(false),
            $statusCode,
            $response->getHeaders(false),
        );
    }

    private function checkAndRefreshToken($session): bool
    {
        // Check if access token is expired
        $accessTokenExpiresAt = $session->get("ewop_token_expires_at");
        if ($accessTokenExpiresAt && time() > $accessTokenExpiresAt - 5) {
            // Access token is expired, get a new access token
            $refreshToken = $session->get("ewop_refresh_token");

            if (!$refreshToken) {
                return false; // No refresh token available, cannot refresh access token
            }

            // Check if refresh token is expired
            $refreshTokenExpiresAt = $session->get(
                "ewop_refresh_token_expires_at"
            );
            if ($refreshTokenExpiresAt && time() > $refreshTokenExpiresAt - 5) {
                return false; // Refresh token is also expired, cannot refresh
            }

            $refreshTokenUrl = $_SERVER["EWOP_TOKEN_URL"];
            $clientId = $_SERVER["EWOP_CLIENT_ID"];
            $clientSecret = $_SERVER["EWOP_CLIENT_SECRET"];

            $response = $this->httpClient->request("POST", $refreshTokenUrl, [
                "body" => [
                    "grant_type" => "refresh_token",
                    "client_id" => $clientId,
                    "client_secret" => $clientSecret,
                    "refresh_token" => $refreshToken,
                ],
            ]);
            $data = json_decode($response->getContent(), true);
            if ($response->getStatusCode() === 200) {
                $this->tokenResponseToSession($session, $data);
                return true; // Access token successfully refreshed
            }
            return false; // Refresh failed for some reason
        }
        return true; // Access token is still valid or not expired yet
    }

    private function tokenResponseToSession($session, $data)
    {
        $expiresIn = $data["expires_in"];
        $session->set("ewop_token_expires_at", time() + $expiresIn);

        $refreshTokenExpiresIn = $data["refresh_expires_in"];
        $session->set(
            "ewop_refresh_token_expires_at",
            time() + $refreshTokenExpiresIn
        );

        $session->set("ewop_access_token", $data["access_token"]);
        $session->set("ewop_refresh_token", $data["refresh_token"]);
        $session->set("ewop_id_token", $data["id_token"]);
    }

    private function generateRandomString($length = 20)
    {
        $characters =
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $charactersLength = strlen($characters);
        $randomString = "";
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }
}
