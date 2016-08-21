using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace ValidateJwt
{
    class Program
    {
        static void Main(string[] args)
        {
            RSACryptoServiceProvider publicAndPrivate = new RSACryptoServiceProvider();
            RsaKeyGenerationResult keyGenerationResult = GenerateRsaKeys();

            publicAndPrivate.FromXmlString(keyGenerationResult.PublicAndPrivateKey);
            JwtSecurityToken jwtToken = new JwtSecurityToken
                (issuer: "http://issuer.com", audience: "http://mysite.com"
                , claims: new List<Claim>() { new Claim(ClaimTypes.Name, "Some Name") }
                , expires: new DateTime(2030, 1, 1)
                , notBefore: new DateTime(2010, 1, 1)
                , signingCredentials: new SigningCredentials(new RsaSecurityKey(publicAndPrivate), SecurityAlgorithms.RsaSha256Signature));

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            string tokenString = tokenHandler.WriteToken(jwtToken);

            Console.WriteLine("Token string: {0}", tokenString);

            Validate(tokenString, keyGenerationResult.PublicKeyOnly);

            Console.ReadLine();
        }

        public static void Validate(string token, string publicKey)
        {
            RSACryptoServiceProvider publicOnly = new RSACryptoServiceProvider();
            publicOnly.FromXmlString(publicKey);
            TokenValidationParameters validationParameters = new TokenValidationParameters()
            {
                ValidIssuer = "http://issuer.com"
                , ValidAudience = "http://mysite.com"
                , IssuerSigningKey = new RsaSecurityKey(publicOnly)
            };

            JwtSecurityTokenHandler recipientTokenHandler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken;
            ClaimsPrincipal claimsPrincipal = recipientTokenHandler.ValidateToken(token, validationParameters, out validatedToken);

            Console.WriteLine(validatedToken.Issuer);
        }

        public class RsaKeyGenerationResult
        {
            public string PublicKeyOnly { get; set; }
            public string PublicAndPrivateKey { get; set; }
        }

        private static RsaKeyGenerationResult GenerateRsaKeys()
        {
            // todo: replace with cert

            RSACryptoServiceProvider myRSA = new RSACryptoServiceProvider(2048);
            RsaKeyGenerationResult result = new RsaKeyGenerationResult();
            result.PublicAndPrivateKey = myRSA.ToXmlString(true);
            result.PublicKeyOnly = myRSA.ToXmlString(false);
            return result;
        }
    }
}
