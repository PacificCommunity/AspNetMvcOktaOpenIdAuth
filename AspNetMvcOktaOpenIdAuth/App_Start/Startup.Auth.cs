using System;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Google;
using Owin;
using AspNetMvcOktaOpenIdAuth.Models;
using System.Configuration;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Threading.Tasks;

namespace AspNetMvcOktaOpenIdAuth
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Franck: Loading OpenID Settings
            string applicationCookieName = ConfigurationManager.AppSettings["ApplicationCookieName"] as string;
            string oidcClientId = ConfigurationManager.AppSettings["OpenIDConnect_ClientId"] as string;
            string oidcClientSecret = ConfigurationManager.AppSettings["OpenIDConnect_ClientSecret"];
            string oidcAuthority = ConfigurationManager.AppSettings["OpenIDConnect_Authority"] as string;
            string oidcResponseType = ConfigurationManager.AppSettings["OpenIDConnect_ResponseType"] as string;
            var tokenEndpoint = ConfigurationManager.AppSettings["OpenIDConnect_TokenEndpoint"] as string;

            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });            
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                AuthenticationType = "Okta",
                ClientId = oidcClientId,
                Authority = oidcAuthority,
                ResponseType = oidcResponseType,
                Scope = "openid profile offline_access",

                Notifications = new OpenIdConnectAuthenticationNotifications()
                {

                    AuthenticationFailed = (context) =>
                    {
                        context.HandleResponse();
                        context.Response.Redirect(context.Request.PathBase + "/Account/Login");
                        return Task.FromResult(0);
                    },

                    RedirectToIdentityProvider = (context) =>
                    {
                        // Here we set automatically the RedirectUri (callback) to baseUrl/Account/Okta
                        if (context.Request.Path.Value == "/Account/OktaLogin")
                        {
                            string appBaseUrl = ((context.Request.Host.Value.Contains("localhost")) ?
                                context.Request.Scheme : "https") + "://" + context.Request.Host + context.Request.PathBase;
                            context.ProtocolMessage.RedirectUri = appBaseUrl + "/Account/Okta";
                            context.ProtocolMessage.PostLogoutRedirectUri = appBaseUrl;

                            if (context.Request.QueryString.HasValue)
                                context.ProtocolMessage.State = StringHelper.ToBase64(System.Text.Encoding.UTF8, context.Request.QueryString.Value);
                        }
                        else
                        {
                            //This is to avoid being redirected to the okta login page and handle the logout
                            context.State = Microsoft.Owin.Security.Notifications.NotificationResultState.Skipped;
                            context.HandleResponse();
                        }
                        return Task.FromResult(0);
                    },
                }
            });

            // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // Enables the application to remember the second login verification factor such as phone or email.
            // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
            // This is similar to the RememberMe option when you log in.
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            //app.UseFacebookAuthentication(
            //   appId: "",
            //   appSecret: "");

            //app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions()
            //{
            //    ClientId = "",
            //    ClientSecret = ""
            //});
        }
    }
}