// Intentionally vulnerable ASP.NET controller for the fixture.
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApp;

public class OrdersController : Controller
{
    public IActionResult List(string term)
    {
        // cs-sql-concat: interpolated statement handed to SqlCommand
        using var cmd = new SqlCommand($"SELECT * FROM Orders WHERE Name = '{term}'");
        return Ok(cmd.ExecuteReader());
    }

    public IActionResult Report(string name)
    {
        // cmd-cs-process: composed command via cmd.exe
        Process.Start("cmd.exe", "/c tar -czf /tmp/report.tar " + name);
        return Ok();
    }

    public IActionResult Download(string name)
    {
        // path-traversal: request data used to build the path
        return File(System.IO.File.ReadAllText("/srv/data/" + Request.Query["name"]), "text/plain");
    }

    public IActionResult Preview()
    {
        // ssrf: outbound request to a request-supplied URL
        var client = new HttpClient();
        client.GetAsync(Request.Query["url"]);
        return Ok();
    }

    public IActionResult Greet()
    {
        // xss-response-request: request data written into the response body
        Response.Write("<h1>" + Request.Query["name"] + "</h1>");
        return Ok();
    }

    public IActionResult Restore(Stream body)
    {
        // unsafe-deserialization: BinaryFormatter on untrusted input
        var formatter = new BinaryFormatter();
        return Ok(formatter.Deserialize(body));
    }

    public string Digest(string password)
    {
        // weak-password-hashing: fast digest for a password
        using var md5 = MD5.Create();
        return Convert.ToBase64String(md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)));
    }

    public IActionResult Order()
    {
        // idor: record loaded by a client-supplied identifier
        return Ok(repository.Find(Request.Query["id"]));
    }

    public IActionResult Promote()
    {
        // missing-authorization: role taken from the request
        Role = Request.Query["role"];
        return Ok();
    }
}
