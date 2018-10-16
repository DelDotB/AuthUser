using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using AuthUser.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using ASPNetCoreIdentity.Models.AccountViewModels;

namespace AuthUser.Controllers
{
	public class AccountController : Controller
	{
		private readonly UserManager<ApplicationUser> _userManager;
		private readonly SignInManager<ApplicationUser> _signInManager;
		private readonly RoleManager<IdentityRole> _roleManager;
		private readonly ILogger _logger;

		public AccountController(
			UserManager<ApplicationUser> userManager,
			SignInManager<ApplicationUser> signInManager,
			RoleManager<IdentityRole> roleManager,
			ILogger logger
			)
		{
			_userManager = userManager;
			_signInManager = signInManager;
			_roleManager = roleManager;
			_logger = logger;

			AddRoles();
		}

		private void AddRoles()
		{
			if (!_roleManager.RoleExistsAsync(Helper.Constants.NormalRoleName).Result)
			{
				var roleResult = _roleManager.CreateAsync(new IdentityRole { Name = Helper.Constants.NormalRoleName }).Result;
			}
			if (!_roleManager.RoleExistsAsync(Helper.Constants.AdminRoleName).Result)
			{
				var roleResult = _roleManager.CreateAsync(new IdentityRole { Name = Helper.Constants.AdminRoleName }).Result;
			}

		}

		public IActionResult Index()
		{
			return View();
		}

		[HttpGet]
		[AllowAnonymous]
		public IActionResult Register(string returnUrl = null)
		{
			ViewData["ReturnUrl"] = returnUrl;
			return View();
		}

		[HttpPost]
		[AllowAnonymous]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
		{
			ViewData["ReturnUrl"] = returnUrl;

			if( ModelState.IsValid)
			{
				var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
				int userCount = -_userManager.Users.Count();
				var result = await _userManager.CreateAsync(user, model.Password);

				if( result.Succeeded)
				{
					if (userCount == 0)
					{
						await _userManager.AddToRoleAsync(user, Helper.Constants.AdminRoleName);
					}
					else
					{
						await _userManager.AddToRoleAsync(user, Helper.Constants.NormalRoleName);
					}

					_logger.LogInformation("user created a new account with password");

					await _signInManager.SignInAsync(user, isPersistent: false);
					_logger.LogInformation("New user logged in");

					return RedirectToAction(returnUrl);
				}
				//AddError(result);

			}

			// if swe got this far, something failed. Redisplay form.
			return View(model);
		}

		private IActionResult RedirectToLocal(string returnUrl)
		{
			if( Url.IsLocalUrl(returnUrl))
			{
				return Redirect(returnUrl);
			}
			else
			{
				return RedirectToAction(nameof(HomeController.Index), "Home");
			}
		}

	}
}