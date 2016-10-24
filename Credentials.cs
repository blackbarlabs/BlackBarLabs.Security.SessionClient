using System;
using System.Net;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using BlackBarLabs.Core.Web;
using BlackBarLabs.Security.Session;
using Microsoft.Azure;
using BlackBarLabs.Core.Extensions;

namespace BlackBarLabs.Security.SessionClient
{
    [DataContract]
    public static class Credentials
    {
        [DataContract]
        internal class Credential : ICredential
        {
            #region Properties
            
            [DataMember]
            public Guid AuthorizationId { get; set; }

            [DataMember]
            public CredentialValidationMethodTypes Method { get; set; }

            [DataMember]
            public Uri Provider { get; set; }

            [DataMember]
            public string UserId { get; set; }

            [DataMember]
            public string Token { get; set; }

            [DataMember]
            public Uri[] ClaimsProviders { get; set; }

            #endregion
        }

        private static WebRequest GetRequest()
        {
            var authServerLocation =  CloudConfigurationManager.GetSetting("BlackBarLabs.Security.AuthorizationClient.ServerUrl");
            var webRequest = WebRequest.Create(authServerLocation + "/api/Credential");
            return webRequest;
        }
        
        public async static Task<TResult> CreateImplicitAsync<TResult>(Guid authId, Uri providerId,
            string username, string password,
            Func<TResult> onSuccess,
            Func<Uri, TResult> alreadyExists,
            Func<string, TResult> onFailure)
        {
            var credentialImplicit = new Credential
            {
                AuthorizationId = authId,
                Method = CredentialValidationMethodTypes.Implicit,
                Provider = providerId,
                Token = password,
                UserId = username,
            };
            var webRequest = GetRequest();
            return await webRequest.PostAsync(credentialImplicit,
                (response) => onSuccess(), // TODO: auth header cookies
                (code, response) =>
                {
                    if(code == HttpStatusCode.Conflict)
                    {
                        Uri location;
                        if (Uri.TryCreate(response, UriKind.Absolute, out location))
                            return alreadyExists(location);
                    }
                    return onFailure(response);
                },
                (whyFailed) => onFailure(whyFailed));
        }
        
        public static async Task<T> UpdateImplicitAsync<T>(Guid authId, Uri providerId,
            string username, string password,
            Func<T> onSuccess, Func<string, T> onFailure)
        {
            var credentialImplicit = new Credential
            {
                AuthorizationId = authId,
                Method = CredentialValidationMethodTypes.Implicit,
                Provider = providerId,
                Token = password,
                UserId = username,
            };
            var webRequest = GetRequest();
            return await webRequest.PutAsync(credentialImplicit,
                (response) => onSuccess(), // TODO: auth header cookies
                (code, response) => onFailure(response),
                (whyFailed) => onFailure(whyFailed));
        }

        public delegate TResult CreateVoucherDelegate<TResult>(string token);
        public async static Task<T> CreateVoucherAsync<T>(Guid authId, Uri providerId,
            TimeSpan voucherDuration,
            CreateVoucherDelegate<T> onSuccess, Func<string, T> onFailure)
        {
            var result = await Tokens.VoucherTools.GenerateToken(authId, DateTime.UtcNow + voucherDuration,
                async (token) =>
                {
                    var credentialVoucher = new Credential
                    {
                        AuthorizationId = authId,
                        Method = CredentialValidationMethodTypes.Voucher,
                        Provider = providerId,
                        Token = token,
                        UserId = authId.ToString("N"),
                    };
                    var webRequest = GetRequest();
                    return await webRequest.PostAsync(credentialVoucher,
                        (response) => onSuccess(token),
                        (code, response) => onFailure(response),
                        (whyFailed) => onFailure(whyFailed));
                },
                (setting) => onFailure("Server missing configuration setting:" + setting).ToTask(),
                (setting, issue) => onFailure("Server misconfigured:\nsetting:" + setting + "\nissue:" + issue).ToTask());
            return result;
        }
    }
}