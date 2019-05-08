// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Bot.Builder;
using Microsoft.Bot.Schema;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Microsoft.BotBuilderSamples
{
    /// <summary>
    /// Represents a bot that processes incoming activities.
    /// For each user interaction, an instance of this class is created and the OnTurnAsync method is called.
    /// This is a Transient lifetime service. Transient lifetime services are created
    /// each time they're requested. Objects that are expensive to construct, or have a lifetime
    /// beyond a single turn, should be carefully managed.
    /// For example, the <see cref="MemoryStorage"/> object and associated
    /// <see cref="IStatePropertyAccessor{T}"/> object are created with a singleton lifetime.
    /// </summary>
    /// <seealso cref="https://docs.microsoft.com/en-us/aspnet/core/fundamentals/dependency-injection?view=aspnetcore-2.1"/>
    public class MyBot : IBot
    {
        //Login to the portal with the Admmin (Web Role) credentials and use "<portal_url>/_services/auth/publickey" to get the public key associated with the portal. This key will be used to decrypt the token.
        string publicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAA-----END PUBLIC KEY-----";
        /// <summary>
        /// Initializes a new instance of the <see cref="MyBot"/> class.
        /// </summary>                        
        public MyBot()
        {
        }

        /// <summary>
        /// Every conversation turn calls this method.
        /// </summary>
        /// <param name="turnContext">A <see cref="ITurnContext"/> containing all the data needed
        /// for processing this conversation turn. </param>
        /// <param name="cancellationToken">(Optional) A <see cref="CancellationToken"/> that can be used by other objects
        /// or threads to receive notice of cancellation.</param>
        /// <returns>A <see cref="Task"/> that represents the work queued to execute.</returns>
        /// <seealso cref="BotStateSet"/>
        /// <seealso cref="ConversationState"/>
        public async Task OnTurnAsync(ITurnContext turnContext, CancellationToken cancellationToken = default(CancellationToken))
        {
            // Handle Message activity type, which is the main activity type for shown within a conversational interface
            // Message activities may contain text, speech, interactive cards, and binary or unknown attachments.
            // see https://aka.ms/about-bot-activity-message to learn more about the message and other activity types
            if (turnContext.Activity.Type == ActivityTypes.Message)
            {
                // Echo back to the user whatever they typed.
                var responseMessage = $"You said '{turnContext.Activity.Text}'\n";
                await turnContext.SendActivityAsync(responseMessage);
            }
            else
            {
               // await turnContext.SendActivityAsync($"{turnContext.Activity.Type} event detected");
            }

            //This is the event to send the token to the bot app.
            if (turnContext.Activity.Name == "webchat/join")
            {
                //Parse the incoming activity and get the token.
                dynamic token = JObject.Parse(turnContext.Activity.Value.ToString());
                string accessToken = token.accessToken.ToString();              

                //Check if the token is valid and further get the claim.
                var claims = GetClaimsIfJWTIsValid(publicKey, accessToken);
                var identity = claims.Identity as ClaimsIdentity;
                var name = identity.FindFirst(ClaimTypes.GivenName).Value;

                //The claim contians the Given name of the user. Retrieve it construct a message and show it to the user.
                await turnContext.SendActivityAsync("Hello " + name + "! How can I help you?");
            }
        }

        public ClaimsPrincipal GetClaimsIfJWTIsValid(string fullKey, string jwtToken)
        {
            var rs256Token = fullKey.Replace("-----BEGIN PUBLIC KEY-----", "");
            rs256Token = rs256Token.Replace("-----END PUBLIC KEY-----", "");
            rs256Token = rs256Token.Replace("\n", "");

            //validate the token and get the claims
            return Validate(jwtToken, rs256Token);           
        }

        private ClaimsPrincipal Validate(string token, string key)
        {
            var keyBytes = Convert.FromBase64String(key);

            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParameters);
                
                //Validating the claim
                var validationParameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    RequireSignedTokens = true, //We only accept the Signed token, if the token is not signed, we are not the intended recipient the portals token will always be signed.
                    ValidAudience = "", //Provide the client id (app id) here. This will ensure that the incoming "Audience" value in the claim matches our client id.
                    ValidIssuer = ".microsoftcrmportals.com", //Provide the Issuer here. This is typicaly your portal's home page url. This will ensure that we received the token from the right issuer.
                    ValidateLifetime = true,
                    LifetimeValidator = CustomLifetimeValidator, //Validate the expiry time stamp of the token
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    IssuerSigningKey = new RsaSecurityKey(rsa) //Portal will use a private key to sign the token which will be decrypted by using the public token. Ensuring that the token is signed appropriately.
                };
                var handler = new JwtSecurityTokenHandler();

                //Validating the token, extracing the claims.
                var claims = handler.ValidateToken(token, validationParameters, out var validatedToken);
                return claims;
            }
        }

        private bool CustomLifetimeValidator(DateTime? notBefore, DateTime? expires, SecurityToken token, TokenValidationParameters @params)
        {
            if (expires != null)
            {
                return expires > DateTime.UtcNow;
            }
            return false;
        }
    }
}
