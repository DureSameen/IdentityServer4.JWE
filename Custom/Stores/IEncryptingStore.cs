using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer4.JWE.Customization.Stores
{
    /// <summary>
    /// Interface for a encrypting credential store
    /// </summary>
    public interface IEncryptingStore
    {
        /// <summary>
        /// Gets the encrypting credentials.
        /// </summary>
        /// <returns></returns>
        Task<EncryptingCredentials> GetEncryptingCredentialsAsync();
    }
}