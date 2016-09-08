using System;
using System.Net;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using BlackBarLabs.Core;
using BlackBarLabs.Core.Web;
using BlackBarLabs.Security.Session;
using Microsoft.Azure;

namespace BlackBarLabs.Security.SessionClient
{
    public static class Sessions
    {
        [DataContract]
        private class Session : ISession
        {
            [DataMember]
            public Guid Id { get; set; }

            [DataMember]
            public Guid AuthorizationId { get; set; }

            [DataMember]
            public ICredential Credentials { get; set; }
            
            [DataMember]
            public string RefreshToken { get; set; }

            [DataMember]
            public AuthHeaderProps SessionHeader { get; set; }
        }

        private static TResult GetRequest<TResult>(Func<WebRequest, TResult> callback)
        {
            var authServerLocation =  CloudConfigurationManager.GetSetting("BlackBarLabs.Security.AuthorizationClient.ServerUrl");
            var webRequest = WebRequest.Create(authServerLocation + "/api/Session");
            return callback(webRequest);
        }

        private async static Task<TResult> FetchSessionTokenAsync<TResult>(Session session,
            Func<string, string, TResult> success, Func<string, TResult> failure)
        {
            return await GetRequest(
                async (webRequest) =>
                {
                    return await webRequest.PostAsync(session,
                        (response) =>
                        {
                            var responseText = new System.IO.StreamReader(response.GetResponseStream()).ReadToEnd();
                            var responseSession = Newtonsoft.Json.JsonConvert.DeserializeObject<Session>(responseText);
                            if(default(Session) == responseSession ||
                               default(AuthHeaderProps) == responseSession.SessionHeader)
                            {
                                return failure("Response was not a session");
                            }
                            return success(responseSession.SessionHeader.Name, responseSession.SessionHeader.Value);
                        },
                        (responseCode, response) => failure(response),
                        (whyFailed) => failure(whyFailed));
                });
        }

        public async static Task<TResult> CreateWithVoucherAsync<TResult>(Guid authId, string authToken,
            Func<string, string, TResult> success, Func<string, TResult> failure)
        {
            var providerId =  CloudConfigurationManager.GetSetting("BlackbarLabs.Security.CredentialProvider.Voucher.provider").ToUri();

            var credentialVoucher = new Credentials.Credential
            {
                Method = CredentialValidationMethodTypes.Voucher,
                Provider = providerId,
                Token = authToken,
                UserId = authId.ToString("N"),
            };

            var session = new Session()
            {
                Id = Guid.NewGuid(),
                Credentials = credentialVoucher,
            };

            return await FetchSessionTokenAsync(session,
                (headerName, headerValue) => success(headerName, headerValue),
                (whyFailed) => failure(whyFailed));
        }
        
        public async static Task<TResult> CreateWithImplicitAsync<TResult>(string username, string password,
            Func<string, string, TResult> success, Func<string, TResult> failure)
        {
            var providerId =  CloudConfigurationManager.GetSetting("BlackbarLabs.Security.CredentialProvider.Implicit.provider").ToUri();

            var credentialImplicit = new Credentials.Credential
            {
                Method = CredentialValidationMethodTypes.Implicit,
                Provider = providerId,
                Token = password,
                UserId = username,
            };

            var session = new Session()
            {
                Id = Guid.NewGuid(),
                Credentials = credentialImplicit,
            };

            return await FetchSessionTokenAsync(session,
                (headerName, headerValue) => success(headerName, headerValue),
                (whyFailed) => failure(whyFailed));
        }
    }
}
