using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Azure;

namespace BlackBarLabs.Security.SessionClient
{
    public class Context : IContext
    {
        public Task<TResult> ClaimGetAsync<TResult>(Guid authorizationId, Uri type,
            Func<Guid, Uri, string, TResult> success, 
            Func<TResult> notFound,
            Func<HttpStatusCode, string, TResult> webFailure, 
            Func<string, TResult> failure)
        {
            return Claims.GetAsync(authorizationId, type,
                success,
                notFound,
                webFailure,
                failure);
        }

        public Task<TResult> ClaimPostAsync<TResult>(Guid authorizationId, Uri type, string value,
            Func<TResult> success,
            Func<HttpStatusCode, string, TResult> webFailure,
            Func<string, TResult> failure)
        {
            return Claims.PostAsync(authorizationId, type, value,
                success,
                webFailure,
                failure);
        }

        public Task<TResult> ClaimPutAsync<TResult>(Guid authorizationId, Uri type, string value,
            Func<TResult> success,
            Func<TResult> notFound,
            Func<HttpStatusCode, string, TResult> httpError,
            Func<string, TResult> failure)
        {
            return Claims.PutAsync(authorizationId, type, value,
                success,
                notFound,
                httpError,
                failure);
        }

        public Task<TResult> CreateAuthorizationAsync<TResult>(Guid authorizationId, Func<TResult> onSuccess, Func<string, TResult> onFailure)
        {
            return Authorizations.CreateAsync(authorizationId,
                onSuccess, onFailure);
        }

        public Task<TResult> AuthorizationDeleteAsync<TResult>(Guid id, Func<TResult> success, Func<HttpStatusCode, string, TResult> webFailure, Func<TResult> failure)
        {
            return Authorizations.DeleteAsync(id, success, webFailure, failure);
        }

        public Task<TResult> CreateSessionsWithImplicitAsync<TResult>(string username, string password, Func<string, string, TResult> success, Func<string, TResult> failed)
        {
            return Sessions.CreateWithImplicitAsync(username, password, success, failed);
        }

        public Task<TResult> CreateSessionsWithTokenAsync<TResult>(Guid userId, string token, Func<string, string, TResult> success, Func<string, TResult> failure)
        {
            return Sessions.CreateWithVoucherAsync(userId, token, success, failure);
        }

        public Task<TResult> CreateCredentialVoucherAsync<TResult>(Guid authorizationId, TimeSpan timeSpan, Func<string, TResult> success, Func<string, TResult> failure)
        {
            var voucherProviderString =  CloudConfigurationManager.GetSetting("BlackbarLabs.Security.CredentialProvider.Voucher.provider");
            var voucherProviderUri = new Uri(voucherProviderString);
            return Credentials.CreateVoucherAsync(authorizationId, voucherProviderUri, timeSpan,
                (token) => success(token), failure);
        }

        public Task<TResult> CreateCredentialImplicitAsync<TResult>(Guid authorizationId, string username, string password,
            Func<TResult> success,
            Func<Uri, TResult> alreadyExists,
            Func<string, TResult> failure)
        {
            var implicitProviderString =  CloudConfigurationManager.GetSetting("BlackbarLabs.Security.CredentialProvider.Implicit.provider");
            var implicitProviderUri = new Uri(implicitProviderString);
            return Credentials.CreateImplicitAsync(authorizationId, implicitProviderUri, username, password,
                success,
                alreadyExists,
                failure);
        }

        public Task<TResult> UpdateCredentialImplicitAsync<TResult>(Guid authorizationId, string username, string password,
          Func<TResult> success, Func<string, TResult> failure)
        {
            var implicitProviderString =  CloudConfigurationManager.GetSetting("BlackbarLabs.Security.CredentialProvider.Implicit.provider");
            var implicitProviderUri = new Uri(implicitProviderString);
            return Credentials.UpdateImplicitAsync(authorizationId, implicitProviderUri, username, password,
                success, failure);
        }

    }
}
