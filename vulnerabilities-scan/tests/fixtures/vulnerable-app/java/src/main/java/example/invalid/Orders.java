// Intentionally vulnerable Java servlet for the fixture.
package example.invalid;

import java.io.File;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Orders {

  public void list(HttpServletRequest request, HttpServletResponse response) throws Exception {
    // java-sql-concat: statement composed with + concatenation
    stmt.executeQuery("SELECT * FROM orders WHERE id = " + request.getParameter("term"));
  }

  public void report(String cmd) throws Exception {
    // cmd-java-runtime: composed command handed to Runtime.exec
    Runtime.getRuntime().exec("tar -czf /tmp/report.tar " + cmd);
  }

  public void download(HttpServletRequest request, HttpServletResponse response) throws Exception {
    // path-traversal: request data used to build the path
    File file = new File("/srv/data/" + request.getParameter("name"));
    response.getOutputStream().write(java.nio.file.Files.readAllBytes(file.toPath()));
  }

  public void preview(HttpServletRequest request) throws Exception {
    // ssrf: outbound request to a request-supplied URL
    new URL(request.getParameter("url")).openConnection().getInputStream();
  }

  public void greet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    // xss-response-request: request data written into the response body
    response.getWriter().print("<h1>" + request.getParameter("name") + "</h1>");
  }

  public void restore(ObjectInputStream in) throws Exception {
    // unsafe-deserialization: native deserialization of untrusted bytes
    Object state = in.readObject();
  }

  public String digest(String password) throws Exception {
    // weak-password-hashing: fast digest for a password
    MessageDigest md = MessageDigest.getInstance("MD5");
    return new String(md.digest(password.getBytes()));
  }

  public String identity(HttpServletRequest request) {
    // missing-authentication: identity from an unverified header
    return request.getHeader("X-User-Id");
  }

  public String role(HttpServletRequest request) {
    // missing-authorization: role taken from the request
    String role = request.getParameter("role");
    return role;
  }

  public Object order(HttpServletRequest request) {
    // idor: record loaded by a client-supplied identifier
    return repository.findById(request.getParameter("id"));
  }

  @CrossOrigin(origins = "*")
  public void upload(MultipartFile part) throws Exception {
    // upload-filename: stored under the client-supplied name
    part.transferTo(new File("/srv/uploads/" + part.getOriginalFilename()));
  }
}
