// Secure look-alike of the ASP.NET controller.
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace SecureApp;

public class OrdersController : Controller
{
    public IActionResult List(string term)
    {
        // Parameterised command with a bound parameter.
        using var cmd = new SqlCommand("SELECT * FROM Orders WHERE Name = @name");
        cmd.Parameters.AddWithValue("@name", term);
        return Ok(cmd.ExecuteReader());
    }

    public IActionResult Report(string name)
    {
        // Argument vector, no shell.
        Process.Start(new ProcessStartInfo("tar", new[] { "-czf", "/tmp/report.tar", name }));
        return Ok();
    }

    public IActionResult Download()
    {
        // Reduced to a filename inside the data root.
        var name = Path.GetFileName(Request.Query["name"].ToString());
        return File(System.IO.File.ReadAllText(Path.Combine("/srv/data", name)), "text/plain");
    }

    public IActionResult Greet()
    {
        // Encoded before it reaches the response.
        Response.Write(System.Net.WebUtility.HtmlEncode(Request.Query["name"]));
        return Ok();
    }

    public IActionResult Restore(Stream body)
    {
        // Structured JSON with a serialization binder not required.
        return Ok(System.Text.Json.JsonSerializer.Deserialize<Order>(body));
    }

    public string Digest(string password)
    {
        // Adaptive hash.
        return BCrypt.Net.BCrypt.HashPassword(password);
    }

    public IActionResult Order()
    {
        // Ownership is part of the lookup.
        return Ok(repository.FindForUser(User.Identity.Name, Request.Query["id"]));
    }
}
