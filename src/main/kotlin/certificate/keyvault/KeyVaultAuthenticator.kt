package certificate.keyvault

import certificate.Config
import com.microsoft.aad.adal4j.AuthenticationContext
import com.microsoft.aad.adal4j.AuthenticationResult
import com.microsoft.aad.adal4j.ClientCredential
import com.microsoft.azure.keyvault.KeyVaultClient
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials
import com.microsoft.rest.credentials.ServiceClientCredentials
import java.net.MalformedURLException
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future


/**
 * Authenticates to Azure Key Vault by providing a callback to authenticate
 * using adal.
 *
 * @author tifchen
 */
object KeyVaultAuthenticator {

    //Creates the KeyVaultClient using the created credentials.
//    val authenticatedClient: KeyVaultClient
//        get() = KeyVaultClient(createCredentials())
    val authenticatedClient: KeyVaultClient by lazy {
        KeyVaultClient(createCredentials())
    }

    /**
     * Creates a new KeyVaultCredential based on the access token obtained.
     * @return
     */
    private fun createCredentials(): ServiceClientCredentials {
        return object : KeyVaultCredentials() {

            //Callback that supplies the token type and access token on request.
            override fun doAuthenticate(authorization: String, resource: String, scope: String?): String {

                val authResult: AuthenticationResult
                try {
                    authResult = getAccessToken(authorization, resource)
                    return authResult.accessToken
                } catch (e: Exception) {
                    e.printStackTrace()
                }

                return ""
            }

        }
    }

    /**
     * Private helper method that gets the access token for the authorization and resource depending on which variables are supplied in the environment.
     *
     * @param authorization
     * @param resource
     * @return
     * @throws ExecutionException
     * @throws InterruptedException
     * @throws MalformedURLException
     * @throws Exception
     */
    @Throws(InterruptedException::class, ExecutionException::class, MalformedURLException::class)
    private fun getAccessToken(authorization: String, resource: String): AuthenticationResult {

        val clientId = Config.AZURE_CLIENT_ID
        val clientKey = Config.AZURE_CLIENT_SECRET

        var result: AuthenticationResult? = null

        //Starts a service to fetch access token.
        var service: ExecutorService? = null
        try {
            service = Executors.newFixedThreadPool(1)
            val context = AuthenticationContext(authorization, false, service!!)

            var future: Future<AuthenticationResult>? = null

            //Acquires token based on client ID and client secret.
            if (clientId != null && clientKey != null) {
                val credentials = ClientCredential(clientId, clientKey)
                future = context.acquireToken(resource, credentials, null)
            }

            result = future!!.get()
        } finally {
            service?.shutdown()
        }

        if (result == null) {
            throw RuntimeException("Authentication results were null.")
        }
        return result
    }
}
