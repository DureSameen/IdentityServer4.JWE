using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IdentityServer4.Stores;
using IdentityServer4.JWE.Customization.Stores;
using IdentityServer4.JWE.Customization.Stores.Default;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer4.JWE.Customization.Extensions
{
    /// <summary>
    /// 
    /// </summary>
    public static class EncryptingCredentialsExtension
    {
        /// <summary>
        /// Adds the encrypting credentials.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="credential">The credential.</param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException">Signing key is not asymmetric</exception>
        public static IIdentityServerBuilder AddEncryptingCredentials(this IIdentityServerBuilder builder, EncryptingCredentials credential)
        {
            
            if (!(credential.Key is AsymmetricSecurityKey
                  || credential.Key is JsonWebKey && ((JsonWebKey)credential.Key).HasPrivateKey))
                //&& !credential.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256Signature))
            {
                throw new InvalidOperationException("Signing key is not asymmetric");
            }
            builder.Services.AddSingleton<IEncryptingStore>(new DefaultEncryptingCredentialsStore(credential));
            builder.Services.AddSingleton<IValidationKeysStore>(new DefaultValidationKeysStore(new[] { credential.Key }));

            return builder;
        }

        /// <summary>
        /// Adds the custom validation key.
        /// </summary>
        /// <param name="builder">The builder.</param>
        /// <param name="cert">The cert.</param>
        /// <returns></returns>
        public static IIdentityServerBuilder AddCustomValidationKey(this IIdentityServerBuilder builder, X509Certificate2 cert)
        {
            
          builder.AddValidationKey(cert);
          return builder;
        }
    }
}
