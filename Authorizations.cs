using System;
using System.Net;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using BlackBarLabs.Core.Web;
using BlackBarLabs.Security.Session;
using Microsoft.Azure;

namespace BlackBarLabs.Security.SessionClient
{
    public static class Authorizations
    {
        [DataContract]
        private class Authorization : IAuthorization
        {
            [DataMember]
            public Uri[] CredentialProviders { get; set; }

            [DataMember]
            public Guid Id { get; set; }
        }

        private static WebRequest GetRequest()
        {
            var authServerLocation =  CloudConfigurationManager.GetSetting("BlackBarLabs.Security.AuthorizationClient.ServerUrl");
            var webRequest = WebRequest.Create(authServerLocation + "/api/Authorization");
            return webRequest;
        }

        public async static Task<T> CreateAsync<T>(Guid authId,
            Func<T> onSuccess, Func<string, T> onFailure)
        {
            var auth = new Authorization()
            {
                Id = authId,
            };

            var webRequest = GetRequest();
            return await webRequest.PostAsync(auth,
                (response) => onSuccess(),
                (code, response) => onFailure(String.Format(
                            "POST [{0}] failed with message:[{1}] -- {2}",
                            webRequest.RequestUri, code, response)),
                (whyFailed) => onFailure(String.Format(
                            "POST [{0}] failed with message -- {1}",
                            webRequest.RequestUri, whyFailed)));
        }

        public static async Task<TResult> DeleteAsync<TResult>(Guid authId, 
            Func<TResult> success,
            Func<HttpStatusCode, string, TResult> failedResponse,
            Func<TResult> couldNotConnect)
        {
            var auth = new Authorization()
            {
                Id = authId,
            };

            var webRequest = GetRequest();
            return await webRequest.DeleteAsync(auth,
                (response) => success(),
                (code, response) => failedResponse(code, response),
                (whyFailed) => couldNotConnect());
        }
    }
}
