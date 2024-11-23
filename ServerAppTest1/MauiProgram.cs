using Microsoft.Extensions.Logging;
using ServerAppTest1.Services;


namespace ServerAppTest1;
public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
            });

        builder.Services.AddMauiBlazorWebView();
        // Register SecureStorageService
        builder.Services.AddSingleton<SecureStorageService>();

        // Register AuthMessageHandler
        builder.Services.AddTransient<AuthMessageHandler>();

        builder.Services.AddSingleton<IAlertService, AlertService>();


#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
		builder.Logging.AddDebug();
#endif
        builder.Services.AddSingleton<HttpClient>(sp => new HttpClient
        {
            BaseAddress = new Uri("https://localhost:7078/")
        });

        // Configure HttpClient with AuthMessageHandler
        builder.Services.AddHttpClient("AuthorizedClient", client =>
        {
            client.BaseAddress = new Uri("https://localhost:7078/"); // Base URL for your API
        })
        .AddHttpMessageHandler<AuthMessageHandler>();




        return builder.Build();
    }
}
