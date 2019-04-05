﻿using IdentityServer4.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityServer4.JWE
{

    public class Config
    {
        // clients that are allowed to access resources from the Auth server 
        public static IEnumerable<Client> GetClients() =>
            // client credentials, list of clients
            new List<Client>
                            {
                            new Client
                            {
                            ClientId = "client",
                            AllowedGrantTypes = GrantTypes.ClientCredentials,
 
                            // Client secrets
                            ClientSecrets =
                            {
                            new Secret("secret".Sha256())
                            },
                            AllowedScopes = { "api1" }
                            },
                            };

        // API that are allowed to access the Auth server
        public static IEnumerable<ApiResource> GetApiResources() => new List<ApiResource>
                                        {
                                        new ApiResource("api1", "My API")
                                        };
                                            }
}

