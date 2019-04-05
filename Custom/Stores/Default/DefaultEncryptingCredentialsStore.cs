using Microsoft.IdentityModel.Tokens;
using System.Threading.Tasks;



namespace IdentityServer4.JWE.Customization.Stores.Default
{
    /// <summary>
    /// 
    /// </summary>
    /// <seealso cref="IdentityServer4.JWE.Customization.Stores.IEncryptingStore" />
    public class DefaultEncryptingCredentialsStore : IEncryptingStore
        {
        private readonly EncryptingCredentials _credential;

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultEncryptingCredentialsStore"/> class.
        /// </summary>
        /// <param name="credential">The credential.</param>
        public DefaultEncryptingCredentialsStore(EncryptingCredentials credential)
        {
            _credential = credential;
        }

        /// <summary>
        /// Gets the signing credentials.
        /// </summary>
        /// <returns></returns>
        public Task<EncryptingCredentials> GetEncryptingCredentialsAsync()
        {
            return Task.FromResult(_credential);
        }
    }
}
