using BaseLibrary.DTOs;
using BaseLibrary.Responses;
using ClientLibrary.Helpers;
using ClientLibrary.Services.Contracts;
using System.Net.Http.Json;

namespace ClientLibrary.Services.Implementations
{
    public class UserAccountService(GetHttpClient getHttpClient) : IUserAccountService
    {
        public const string AuthUrl = "api/authentication";
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            var httpClient = getHttpClient.GetPublicHttpClient();
            var response = await httpClient.PostAsJsonAsync($"{AuthUrl}/register", user);
            if(!response.IsSuccessStatusCode) return new GeneralResponse(false, "Error Occurred");

            return await response.Content.ReadFromJsonAsync<GeneralResponse>()!;
        }

        public async Task<LoginResponse> SignInAsync(Login user)
        {
            var httpClient = getHttpClient.GetPublicHttpClient();
            var response = await httpClient.PostAsJsonAsync($"{AuthUrl}/login", user);
            if (!response.IsSuccessStatusCode) return new LoginResponse(false, "Error Occurred");

            return await response.Content.ReadFromJsonAsync<LoginResponse>()!;
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            var httpClient = getHttpClient.GetPublicHttpClient();
            var response = await httpClient.PostAsJsonAsync($"{AuthUrl}/refresh-token", token);
            if (!response.IsSuccessStatusCode) return new LoginResponse(false, "Error Occurred");

            return await response.Content.ReadFromJsonAsync<LoginResponse>()!;
        }

        public async Task<WeatherForecast[]> GetWeatherForecasts()
        {
            var httpClient = await getHttpClient.GetPrivateHttpClient();
            var response = await httpClient.GetFromJsonAsync<WeatherForecast[]>("api/weatherforecast");
            return response!;
        }
    }
}
