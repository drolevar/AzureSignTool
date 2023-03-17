using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;

using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AzureSignTool
{
    internal class KeyVaultConfigurationDiscoverer
    {
        private readonly ILogger _logger;

        public KeyVaultConfigurationDiscoverer(ILogger logger)
        {
            _logger = logger;
        }

        public async Task<ErrorOr<AzureKeyVaultMaterializedConfiguration>> Materialize(AzureKeyVaultSignConfigurationSet configuration)
        {
            TokenCredential credential;
            if (configuration.ManagedIdentity)
            {
                credential = new DefaultAzureCredential();
            }
            else if(!string.IsNullOrWhiteSpace(configuration.AzureAccessToken))
            {
                credential = new AccessTokenCredential(configuration.AzureAccessToken);
            }
            else if (!string.IsNullOrWhiteSpace(configuration.AzureClientCertificateThumbprint))
            {
                try
                {
                    var storeLocation = configuration.AzureClientCertificateSearchMachine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;

                    X509Certificate2 authCert;
                    using (var store = new X509Store(configuration.AzureClientCertificateStore, storeLocation))
                    {
                        store.Open(OpenFlags.ReadOnly);
                        authCert = store.Certificates.FirstOrDefault(cert => string.Equals(cert.Thumbprint, configuration.AzureClientCertificateThumbprint, StringComparison.OrdinalIgnoreCase));
                    }

                    if (authCert == null)
                    {
                        throw new InvalidOperationException($"Failed to locate a personal certificate with hash {configuration.AzureClientCertificateThumbprint}. Please verify the thumbprint of the certificate.");
                    }

                    credential = new ClientCertificateCredential(configuration.AzureTenantId, configuration.AzureClientId, authCert);
                }
                catch (Exception e)
                {
                    _logger.LogError(e.Message);

                    return e;
                }
            }
            else
            {
                credential = new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId, configuration.AzureClientSecret);
            }


            X509Certificate2 certificate;
            KeyVaultCertificateWithPolicy azureCertificate;
            try
            {
                var certClient = new CertificateClient(configuration.AzureKeyVaultUrl, credential);

                _logger.LogTrace($"Retrieving certificate {configuration.AzureKeyVaultCertificateName}.");
                azureCertificate = (await certClient.GetCertificateAsync(configuration.AzureKeyVaultCertificateName).ConfigureAwait(false)).Value;
                _logger.LogTrace($"Retrieved certificate {configuration.AzureKeyVaultCertificateName}.");
                
                certificate = new X509Certificate2(azureCertificate.Cer);
            }
            catch (Exception e)
            {
                _logger.LogError($"Failed to retrieve certificate {configuration.AzureKeyVaultCertificateName} from Azure Key Vault. Please verify the name of the certificate and the permissions to the certificate. Error message: {e.Message}.");
                _logger.LogTrace(e.ToString());
                
                return e;
            }
            var keyId = azureCertificate.KeyId;
            return new AzureKeyVaultMaterializedConfiguration(credential, certificate, keyId);
        }
    }
}
