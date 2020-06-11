using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using LoginReg.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;

namespace LoginReg.Controllers
{
    public class HomeController : Controller
    {
        private MyContext dbContext;

        public HomeController(MyContext context)
        {
            dbContext = context;
        }

// ****************************************************  GET REQUEST ******************************************* // 
        // Register Page, create new User //
        [HttpGet("")]
        public IActionResult Index()
        {
            return View("Index");
        }

        // Login Page, find User in DB and logs in //
        [HttpGet("login")]
        public IActionResult Login()
        {
            return View("login");
        }

        // User page to be seen only when logged in //
        [HttpGet("success")]
        public IActionResult Success()
        {
            string userLoggedIn = HttpContext.Session.GetString("LoggedIn");
            if(userLoggedIn == "true")
            {
                return View("Success");
            }
            else{
                return View("login");
            }
        }

// ****************************************************  POST REQUEST ******************************************* // 
        // Create New User //
        [HttpPost("/createuser")]
        public IActionResult CreateUser(User FromForm)
        {
            if(ModelState.IsValid)
            {
                if(dbContext.Users.Any(u => u.Email == FromForm.Email))
                {
                    ModelState.AddModelError("Email", "Email is already in use!");
                    return Index();
                }
                PasswordHasher<User> Hasher = new PasswordHasher<User>();
                FromForm.Password = Hasher.HashPassword(FromForm, FromForm.Password);
                dbContext.Add(FromForm);
                dbContext.SaveChanges();
                HttpContext.Session.SetString("LoggedIn", "true");
                return RedirectToAction("success");
            }
            else
            {
                return Index();
            }
        }

        // Login Registered User //
        [HttpPost("/finduser")]
        public IActionResult FindUser(LoginUser user)
        {
            if(ModelState.IsValid)
            {
                var userInDb = dbContext.Users.FirstOrDefault(u => u.Email == user.Email);
                if(userInDb == null)
                {
                    ModelState.AddModelError("Email", "Invalid Email/Password");
                    return Login();
                }
                var hasher = new PasswordHasher<LoginUser>();
                var result = hasher.VerifyHashedPassword(user, userInDb.Password, user.Password);
                if(result == 0)
                {
                    ModelState.AddModelError("Password", "Wrong Password");
                    return Login();
                }
                else
                {
                    HttpContext.Session.SetString("LoggedIn", "true");
                    return RedirectToAction("Success");
                }
            }
            else
            {
                return Login();
            }
        }

        // Logout user and redicrect to login page //
        [HttpGet("logout")]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("login");
        }
    }
}
