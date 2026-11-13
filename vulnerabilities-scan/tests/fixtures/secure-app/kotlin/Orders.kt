package example.invalid

import java.io.DataInputStream
import java.io.InputStream
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import javax.servlet.http.HttpServletRequest

class Orders(private val connection: java.sql.Connection) {

    fun findByName(request: HttpServletRequest): List<String> {
        // The statement is constant; the value is bound to the placeholder.
        val statement = connection.prepareStatement("SELECT id FROM orders WHERE name = ?")
        statement.setString(1, request.getParameter("name"))
        return listOf(statement.executeQuery().toString())
    }

    fun archive(name: String) {
        // Argument vector, no shell.
        ProcessBuilder("tar", "-czf", "/tmp/report.tgz", "/srv/data/" + name).start()
    }

    fun restore(stream: InputStream): Int {
        // A length-prefixed read of untrusted bytes, not object deserialisation.
        return DataInputStream(stream).readInt()
    }

    fun hashPassword(password: String): ByteArray {
        // SHA-256, no MD5.
        return MessageDigest.getInstance("SHA-256").digest(password.toByteArray())
    }

    fun readDocument(request: HttpServletRequest): ByteArray {
        // The request value is reduced to a file name and resolved inside the root.
        val name = java.io.File(request.getParameter("name")).name
        val root: Path = Paths.get("/srv/data")
        return java.nio.file.Files.readAllBytes(root.resolve(name))
    }
}
