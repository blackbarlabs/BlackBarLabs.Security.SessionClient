using System;
using System.Net;
using System.Threading.Tasks;

namespace BlackBarLabs.Security.SessionClient
{
    public interface IContext
    {
        Task<TResult> ClaimGetAsync<TResult>(Guid authorizationId, Uri type,
            Func<Guid, Uri, string, TResult> success,
            Func<TResult> notFound, 
            Func<HttpStatusCode, string, TResult> webFailure,
            Func<string, TResult> failure);

        Task<TResult> ClaimPutAsync<TResult>(Guid authorizationId, Uri distributorAdminRole, string value,
            Func<TResult> success,
            Func<TResult> notFound,
            Func<HttpStatusCode, string, TResult> httpError,
            Func<string, TResult> failure);

        Task<TResult> ClaimPostAsync<TResult>(Guid authorizationId, Uri distributorAdminRole, string value,
            Func<TResult> success,
            Func<HttpStatusCode, string, TResult> httpError,
            Func<string, TResult> failure);

        Task<TResult> CreateAuthorizationAsync<TResult>(Guid authorizationId,
            Func<TResult> onSuccess,
            Func<string, TResult> onFailure);

        Task<TResult> CreateSessionsWithImplicitAsync<TResult>(string username, string password,
            Func<string, string, TResult> success,
            Func<string, TResult> failed);

        Task<TResult> CreateSessionsWithTokenAsync<TResult>(Guid userId, string token,
            Func<string, string, TResult> success,
            Func<string, TResult> failure);

        Task<TResult> CreateCredentialVoucherAsync<TResult>(Guid authorizationId, TimeSpan timeSpan,
            Func<string, TResult> success,
            Func<string, TResult> failure);

        Task<TResult> CreateCredentialImplicitAsync<TResult>(Guid authorizationId, string username, string password,
            Func<TResult> success,
            Func<Uri, TResult> alreadyExists,
            Func<string, TResult> failure);

        Task<TResult> UpdateCredentialImplicitAsync<TResult>(Guid authorizationId, string username, string password,
            Func<TResult> success,
            Func<string, TResult> failure);

        Task<TResult> AuthorizationDeleteAsync<TResult>(Guid id,
            Func<TResult> success,
            Func<HttpStatusCode, string, TResult> webFailure,
            Func<TResult> failure);
    }
}
