package example.invalid

import java.io.InputStream
import java.io.ObjectInputStream
import java.nio.file.Paths
import java.security.MessageDigest
import javax.servlet.http.HttpServletRequest

class Orders(private val connection: java.sql.Connection) {

    fun findByName(request: HttpServletRequest): List<String> {
        // The name is concatenated into the statement.
        val name = request.getParameter("name")
        val statement = connection.prepareStatement("SELECT id FROM orders WHERE name = '" + name + "'")
        return listOf(statement.executeQuery().toString())
    }

    fun archive(name: String) {
        // The command is assembled from a value and handed to the JVM shell exec.
        Runtime.getRuntime().exec("tar -czf /tmp/" + name + ".tgz /srv/data")
    }

    fun restore(stream: InputStream) {
        // Untrusted bytes are deserialised straight into objects.
        val restored = ObjectInputStream(stream).readObject()
        println(restored)
    }

    fun hashPassword(password: String): ByteArray =
        MessageDigest.getInstance("MD5").digest(password.toByteArray())

    fun readDocument(request: HttpServletRequest): ByteArray =
        java.nio.file.Files.readAllBytes(Paths.get("/srv/data" + request.getParameter("name")))
}
