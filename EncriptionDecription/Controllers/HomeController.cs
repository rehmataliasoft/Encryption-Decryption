using EncriptionDecription.Generic;
using EncriptionDecription.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting.Internal;
using System.Diagnostics;
using System.Security.Cryptography;

namespace EncriptionDecription.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IWebHostEnvironment _hostingEnvironment;

        public HomeController(ILogger<HomeController> logger, IWebHostEnvironment hostingEnvironment)
        {
            _logger = logger;
            _hostingEnvironment = hostingEnvironment;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
        [HttpPost]
        public IActionResult EncryptFile(IFormFile file, string password)
        {
            try
            {
                byte[]? encryptedBytes = null;
                if (file != null && file.Length > 0)
                {
                    using var memoryStream = new MemoryStream();
                    file.CopyTo(memoryStream);
                    var fileBytes = memoryStream.ToArray();

                    // Perform encryption
                    encryptedBytes = Static.EncryptFileBytes(fileBytes, password);
                    return File(encryptedBytes, "application/octet-stream", file.FileName);
                }
                ModelState.AddModelError("file", "Please select a file.");
                return View();
            }
            catch (Exception ex)
            {
                // Handle exceptions appropriately
                return BadRequest("Encryption failed.");
            }
        }
        [HttpPost]
        public IActionResult DecryptFile(IFormFile file, string password)
        {
            try
            {
                byte[]? decryptedBytes = null;
                if (file != null && file.Length > 0)
                {
                    using var memoryStream = new MemoryStream();
                    file.CopyTo(memoryStream);
                    var fileBytes = memoryStream.ToArray();

                    // Perform decryption
                    decryptedBytes = Static.DecryptFileBytes(fileBytes, password);

                    return File(decryptedBytes, "application/octet-stream", file.FileName);
                }
                ModelState.AddModelError("file", "Please select a file.");
                return View();
            }
            catch (Exception ex)
            {
                // Handle exceptions appropriately
                return BadRequest("Decryption failed.");
            }

        }
        [HttpPost]
        public IActionResult EncryptString(string password, string encryptTextArea)
        {
            try
            {
                string encryptedTextArea = "";
                if (!ReferenceEquals(encryptTextArea, null))
                    encryptedTextArea = Static.EncryptString(encryptTextArea, password);

                var response = new
                {
                    EncryptedTextArea = encryptedTextArea,
                };
                return Json(response);
            }
            catch (Exception ex)
            {
                // Handle exceptions appropriately
                return BadRequest("Encryption failed.");
            }
        }
        [HttpPost]
        public IActionResult DecryptString(string password, string encryptTextArea)
        {
            try
            {
                string decryptedTextArea = "";
                if (!ReferenceEquals(encryptTextArea, null))
                    decryptedTextArea = Static.DecryptString(encryptTextArea, password);

                var response = new
                {
                    DecryptedTextArea = decryptedTextArea,
                };
                return Json(response);
            }
            catch (Exception ex)
            {
                return BadRequest("Decryption failed.");
            }

        }

    }
}