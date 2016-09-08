using System;
using System.Net;
using System.Runtime.Serialization;
using System.Threading.Tasks;
using BlackBarLabs.Core.Web;
using BlackBarLabs.Security.Session;
using Microsoft.Azure;

namespace BlackBarLabs.Security.SessionClient
{
    [DataContract]
    public static class Claims
    {
        [DataContract]
        internal class Claim : IClaim
        {
            #region Properties

            [DataMember]
            public Guid Id { get; set; }

            [DataMember]
            public Guid AuthorizationId { get; set; }

            [DataMember]
            public Uri Issuer { get; set; }
            
            [DataMember]
            public string Signature { get; set; }

            [DataMember]
            public Uri Type { get; set; }

            [DataMember]
            public string Value { get; set; }

            
            #endregion
        }

        internal async static Task<TResult> PutAsync<TResult>(Guid authorizationId, Uri type, string value,
            Func<TResult> success,
            Func<TResult> notFound,
            Func<HttpStatusCode, string, TResult> webFailure,
            Func<string, TResult> failure)
        {
            var claim = new Claim()
            {
                Id = Guid.NewGuid(),
                AuthorizationId = authorizationId,
                Type = type,
                Value = value,
            };

            return await GetRequest(
                async (webRequest) =>
                {
                    return await webRequest.PutAsync(claim,
                        (response) => success(),
                        (code, response) =>
                        {
                            if (HttpStatusCode.NotFound == code)
                                return notFound();
                            return webFailure(code, response);
                        },
                        (whyFailed) => failure(whyFailed));
                });
        }

        internal async static Task<TResult> PostAsync<TResult>(Guid authorizationId, Uri type, string value, 
            Func<TResult> success,
            Func<HttpStatusCode, string, TResult> webFailure,
            Func<string, TResult> failure)
        {
            var claim = new Claim()
            {
                Id = Guid.NewGuid(),
                AuthorizationId = authorizationId,
                Type = type,
                Value = value,
            };

            return await GetRequest(
                async (webRequest) =>
                {
                    return await webRequest.PostAsync(claim,
                        (response) => success(),
                        (code, response) => webFailure(code, String.Format(
                            "POST [{0}] failed with message:[{1}] -- {2}",
                            webRequest.RequestUri, code, response)),
                        (whyFailed) => failure(String.Format(
                            "POST [{0}] failed with message -- {4}", 
                            webRequest.RequestUri, authorizationId, type, value, whyFailed)));
                });
        }
        
        private static TResult GetRequest<TResult>(Func<WebRequest, TResult> callback)
        {
            var authServerLocation =  CloudConfigurationManager.GetSetting("BlackBarLabs.Security.AuthorizationClient.ServerUrl");
            var webRequest = WebRequest.Create(authServerLocation + "/api/Claim");
            return callback(webRequest);
        }

        private static TResult GetRequest<TQuery, TResult>(TQuery query, Func<WebRequest, TResult> callback)
        {
            var authServerLocation =  CloudConfigurationManager.GetSetting("BlackBarLabs.Security.AuthorizationClient.ServerUrl");
            
            var uriBuilder = new UriBuilder(authServerLocation);
            uriBuilder.Path = "/api/Claim";
            var queryParams = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
            foreach(var prop in typeof(TQuery).GetProperties())
            {
                var propValue = prop.GetValue(query);
                if (null == propValue)
                    continue;
                try
                {
                    queryParams[prop.Name] = propValue.ToString();
                } catch(Exception ex)
                {
                    continue;
                }
            }
            uriBuilder.Query = queryParams.ToString();
            var queryUrl = uriBuilder.Uri;
            
            var webRequest = WebRequest.Create(queryUrl);
            return callback(webRequest);
        }

        public static async Task<TResult> GetAsync<TResult>(Guid authorizationId, Uri type,
            Func<Guid, Uri, string, TResult> success,
            Func<TResult> notFound,
            Func<HttpStatusCode, string, TResult> webFailure,
            Func<string, TResult> failure)
        {
            var claim = new Claims.Claim
            {
                AuthorizationId = authorizationId,
                Type = type,
            };

            return await GetRequest(claim,
                async (webRequest) =>
                {
                    return await webRequest.GetAsync(
                        (Claims.Claim[] responseClaims) =>
                        {
                            if (responseClaims.Length > 1)
                                return failure("Expected single claim from query");
                            if (responseClaims.Length == 0)
                                return notFound();

                            var responseClaim = responseClaims[0];
                            if (default(Claim) == responseClaim ||
                               default(Uri) == responseClaim.Type)
                            {
                                return failure("Response was not a claim");
                            }
                            return success(responseClaim.AuthorizationId, responseClaim.Type, responseClaim.Value);
                        },
                        (responseCode, response) =>
                        {
                            if (responseCode == HttpStatusCode.NotFound)
                                return notFound();
                            return webFailure(responseCode, response);
                        },
                        (whyFailed) => failure(whyFailed));
                });
        }
    }
}