using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Threading.Tasks;


namespace ServerAppTest1.Services;
public class AuthMessageHandler : DelegatingHandler
{
    private readonly SecureStorageService _secureStorageService;
    private readonly IHttpClientFactory _httpClientFactory;

    public AuthMessageHandler(SecureStorageService secureStorageService, IHttpClientFactory httpClientFactory)
    {
        _secureStorageService = secureStorageService;
        _httpClientFactory = httpClientFactory;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var accessToken = await _secureStorageService.GetAccessTokenAsync();

        if (!string.IsNullOrEmpty(accessToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        }

        var response = await base.SendAsync(request, cancellationToken);

        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            // Attempt to refresh token
            var isTokenRefreshed = await RefreshTokenAsync();

            if (isTokenRefreshed)
            {
                // Retry the request with new access token
                accessToken = await _secureStorageService.GetAccessTokenAsync();

                if (!string.IsNullOrEmpty(accessToken))
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                }

                // Resend the request
                response.Dispose(); // Dispose the original response
                response = await base.SendAsync(request, cancellationToken);
            }
            else
            {
                // Logout the user
                _secureStorageService.RemoveTokens();
                // Optionally navigate to login page
            }
        }

        return response;
    }

    private async Task<bool> RefreshTokenAsync()
    {
        var refreshToken = await _secureStorageService.GetRefreshTokenAsync();

        if (string.IsNullOrEmpty(refreshToken))
            return false;

        var refreshRequest = new RefreshTokenRequest { RefreshToken = refreshToken };


        var client = _httpClientFactory.CreateClient("AuthorizedClient");
        var response = await client.PostAsJsonAsync("refresh-token", refreshRequest);

        if (response.IsSuccessStatusCode)
        {
            var refreshResponse = await response.Content.ReadFromJsonAsync<RefreshTokenResponse>();

            await _secureStorageService.SetAccessTokenAsync(refreshResponse!.AccessToken);
            await _secureStorageService.SetRefreshTokenAsync(refreshResponse.RefreshToken);

            return true;
        }
        else
        {
            return false;
        }
    }


    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
    }


    public class RefreshTokenResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
    }



}

