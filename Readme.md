# AspNetMvcOktaOpenIdAuth Demo
Code sample demonstrating the use of OpenID Connect with Okta for SPC Accounts
and local user/passwords. Uses the OpenID state parameter to transfer the returnUrl
to the Okta callback

###Setup
1. Open the AspNetMvcOktaOpenIdAuth.sln solution in Visual Studio 2015 and restore all NuGet packages
2. Create an application in Okta (ICT) and obtain ClientId and ClientSecret. Declare localhost:port/Account/Okta and www.spc.int/yoursite/Account/Okta as return URIs
3. Set OpenIDConnect_ClientId and  OpenIDConnect_ClientSecret in Web.Config
4. Compile and run the AspNetMvcOktaOpenIdAuth project. It should open the sample web application at http://localhost:63570

The files modified are 
* App_Start/Startup.Auth.cs
* Controllers/AccountController.cs
* Views/Account/Login.cshtml
* StringHelper.cs

Register with your SPC login (email), then authenticate with Okta
In a real application, you'd probably disable public registration
