// Secure look-alike of the Java servlet.
package example.invalid;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Orders {

  private static final Set<String> ALLOWED_HOSTS = Set.of("api.partner.example");

  public void list(HttpServletRequest request, HttpServletResponse response) throws Exception {
    // Prepared statement with a bound parameter.
    preparedStatement = connection.prepareStatement("SELECT * FROM orders WHERE name = ?");
    preparedStatement.setString(1, request.getParameter("term"));
  }

  public void report(String name) throws Exception {
    // Argument vector, no shell.
    new ProcessBuilder("tar", "-czf", "/tmp/report.tar", name).start();
  }

  public void download(HttpServletRequest request, HttpServletResponse response) throws Exception {
    // Reduced to a filename and confined to the data root.
    Path base = Paths.get("/srv/data").toRealPath();
    Path target = base.resolve(Paths.get(request.getParameter("name")).getFileName());
    response.getOutputStream().write(java.nio.file.Files.readAllBytes(target));
  }

  public void preview(HttpServletRequest request) throws Exception {
    // Only allow-listed hosts are reached.
    String target = request.getParameter("url");
    if (!ALLOWED_HOSTS.contains(new java.net.URL(target).getHost())) {
      throw new IllegalArgumentException("blocked");
    }
  }

  public void restore(java.io.InputStream body) throws Exception {
    // Structured parsing, and a filter is installed for any native read.
    ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("example.invalid.*;!*");
    com.fasterxml.jackson.databind.json.JsonMapper.builder().build().readValue(body, Object.class);
  }

  public String digest(String password) throws Exception {
    // Adaptive hash.
    return BCrypt.hashpw(password, BCrypt.gensalt());
  }

  public String identity(HttpServletRequest request) {
    // Identity comes from the verified principal.
    return request.getUserPrincipal().getName();
  }

  public String role(HttpServletRequest request) {
    // The role is read from the authenticated principal only.
    return request.isUserInRole("admin") ? "admin" : "user";
  }

  public Object order(HttpServletRequest request) {
    // Ownership is part of the lookup.
    return repository.findByOwner(currentPrincipal, request.getParameter("id"));
  }

  @CrossOrigin(origins = "https://app.example.com")
  public void upload(MultipartFile part) throws Exception {
    // Generated name, allow-listed extension.
    String name = UUID.randomUUID() + "." + allowedExtension(part.getOriginalFilename());
    part.transferTo(new File("/srv/uploads/" + name));
  }
}
