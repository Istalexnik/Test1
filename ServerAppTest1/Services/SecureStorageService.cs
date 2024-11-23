using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ServerAppTest1.Services;
public class SecureStorageService
{
    public async Task<string?> GetAccessTokenAsync()
    {
        return await SecureStorage.GetAsync("AccessToken");
    }

    public async Task<string?> GetRefreshTokenAsync()
    {
        return await SecureStorage.GetAsync("RefreshToken");
    }

    public async Task SetAccessTokenAsync(string token)
    {
        await SecureStorage.SetAsync("AccessToken", token);
    }

    public async Task SetRefreshTokenAsync(string token)
    {
        await SecureStorage.SetAsync("RefreshToken", token);
    }

    public void RemoveTokens()
    {
        SecureStorage.Remove("AccessToken");
        SecureStorage.Remove("RefreshToken");
    }
}

