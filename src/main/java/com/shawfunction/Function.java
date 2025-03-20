package com.shawfunction;

import com.microsoft.azure.functions.ExecutionContext;
import com.microsoft.azure.functions.HttpMethod;
import com.microsoft.azure.functions.HttpRequestMessage;
import com.microsoft.azure.functions.HttpResponseMessage;
import com.microsoft.azure.functions.HttpStatus;
import com.microsoft.azure.functions.annotation.AuthorizationLevel;
import com.microsoft.azure.functions.annotation.FunctionName;
import com.microsoft.azure.functions.annotation.HttpTrigger;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.keys.cryptography.models.EncryptResult;
import com.azure.security.keyvault.keys.cryptography.models.EncryptionAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.DecryptResult;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

public class Function {
    @FunctionName("EncryptDecryptFunction")
    public HttpResponseMessage run(
            @HttpTrigger(name = "req", methods = {
                    HttpMethod.GET }, authLevel = AuthorizationLevel.ANONYMOUS) HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {

        context.getLogger().info("Java HTTP trigger processed a request.");

        // Retrieve Key Vault and Key Names from environment variables
        String keyVaultName = System.getenv("KEY_VAULT_NAME");
        String keyName = System.getenv("KEY_NAME");

        // Initialize Key Client
        KeyClient keyClient = new KeyClientBuilder()
                .vaultUrl("https://" + keyVaultName + ".vault.azure.net")
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

        // Retrieve Key
        KeyVaultKey key = keyClient.getKey(keyName);

        // Initialize Cryptography Client
        CryptographyClient cryptoClient = new CryptographyClientBuilder()
                .keyIdentifier(key.getId())
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

        // Read query parameters
        String action = request.getQueryParameters().get("action");
        String data = request.getQueryParameters().get("data");

        if (action == null || data == null) {
            return request.createResponseBuilder(HttpStatus.BAD_REQUEST)
                    .body("Missing action or data in query parameters").build();
        }

        try {
            if ("encrypt".equalsIgnoreCase(action)) {
                
                // Encrypt data
                EncryptResult encryptResult = cryptoClient.encrypt(EncryptionAlgorithm.RSA_OAEP, data.getBytes());
                String encryptedDataBase64 = Base64.getUrlEncoder().encodeToString(encryptResult.getCipherText());

                return request.createResponseBuilder(HttpStatus.OK)
                        .body("{\"encryptedData\":\"" + encryptedDataBase64 + "\"}")
                        .build();
            } else if ("decrypt".equalsIgnoreCase(action)) {
                // URL-safe Base64 decode and decrypt
                byte[] encryptedData = Base64.getUrlDecoder().decode(data);
                DecryptResult decryptResult = cryptoClient.decrypt(EncryptionAlgorithm.RSA_OAEP, encryptedData);

                return request.createResponseBuilder(HttpStatus.OK)
                        .body("{\"decryptedData\":\"" + new String(decryptResult.getPlainText(), StandardCharsets.UTF_8)
                                + "\"}")
                        .build();
            } else {
                return request.createResponseBuilder(HttpStatus.BAD_REQUEST).body("Invalid action").build();
            }
        } catch (Exception e) {
            context.getLogger().severe("Error processing request: " + e.getMessage());
            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error processing request: " + e.getMessage())
                    .build();
        }
    }
}
