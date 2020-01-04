using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.UI.V3.Pages.Account.Internal;
using Microsoft.AspNetCore.Mvc;

namespace ThAmCo.Login.Controllers
{
    public class LoginController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login([FromForm] Models.LoginModel loginModel)
        {
            var client = new HttpClient();

            var disco = await client.GetDiscoveryDocumentAsync("https://localhost:43389");
            var tokenResponse = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = "my_web_app",
                ClientSecret = "secret",

                UserName = loginModel.Email,
                Password = loginModel.Password
            });

            if (tokenResponse.IsError)
                return View(loginModel);

            var userInfoResponse = await client.GetUserInfoAsync(new UserInfoRequest
            {
                Address = disco.UserInfoEndpoint,
                Token = tokenResponse.AccessToken
            });

            if (userInfoResponse.IsError)
                return View(loginModel);

            var claimsIdentity = new ClaimsIdentity(userInfoResponse.Claims, "Identity.Thamco");
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            var tokensToStore = new AuthenticationToken[]
            {
                new AuthenticationToken{ Name = "access_token", Value = tokenResponse.AccessToken }
            };
            var authProperties = new AuthenticationProperties();
            authProperties.StoreTokens(tokensToStore);

            await HttpContext.SignInAsync("Identity.Thamco", claimsPrincipal, authProperties);

            return Redirect("https://localhost:44375/products/Authed");
        }

        [Authorize]
        public IActionResult Authed()
        {
            return Redirect("www.google.com");
        }
    }
}