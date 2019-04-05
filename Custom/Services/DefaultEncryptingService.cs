using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.JWE.Customization.Stores;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer4.JWE.Customization.Services
{
    /// <summary>
    /// 
    /// </summary>
    public interface IEncryptingService
    {
        /// <summary>
        /// Gets the encrypting credentials.
        /// </summary>
        /// <returns></returns>
        Task<EncryptingCredentials> GetEncryptingCredentialsAsync();
    }

    /// <summary>
    /// 
    /// </summary>
    public class DefaultEncryptingService : IEncryptingService
    {
       
            private readonly IEncryptingStore _encryptingCredential;


        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultEncryptingService" /> class.
        /// </summary>
        /// <param name="encryptingCredential">The encrypting credential.</param>
        public DefaultEncryptingService(IEncryptingStore encryptingCredential = null)
            {
            _encryptingCredential = encryptingCredential;
               
            }

        /// <summary>
        /// Gets the encrypting credentials.
        /// </summary>
        /// <returns></returns>
        public async Task<EncryptingCredentials> GetEncryptingCredentialsAsync()
            {
                if (_encryptingCredential != null)
                {
                    return await _encryptingCredential.GetEncryptingCredentialsAsync();
                }

                return null;
            }
        
        }

    }

