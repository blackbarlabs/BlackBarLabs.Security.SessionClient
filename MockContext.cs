using BlackBarLabs.Core.Collections;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BlackBarLabs.Security.SessionClient
{
    public class MockContext : IContext
    {
        static Dictionary<string, Tuple<Guid, Uri, string>> claims = new Dictionary<string, Tuple<Guid, Uri, string>>();
        static private Dictionary<string, Guid> implicitCreds = new Dictionary<string, Guid>();
        static private HashSet<string> usernames = new HashSet<string>();
        static private Dictionary<string, Guid> tokenCreds = new Dictionary<string, Guid>();

        private static string GetClaimKey(Guid authorizationId, Uri type)
        {
            var key = authorizationId.ToString("N") + type.AbsoluteUri;
            return key;
        }

        public async Task<TResult> ClaimGetAsync<TResult>(Guid authorizationId, Uri type,
            Func<Guid, Uri, string, TResult> success,
            Func<TResult> notFound,
            Func<HttpStatusCode, string, TResult> webFailure,
            Func<string, TResult> failure)
        {
            await Task.FromResult(true);
            var key = GetClaimKey(authorizationId, type);
            if (claims.ContainsKey(key))
            {
                var claim = claims[key];
                return success(claim.Item1, claim.Item2, claim.Item3);
            }
            return notFound();
        }

        public async Task<TResult> ClaimPutAsync<TResult>(Guid authorizationId, Uri type, string value,
            Func<TResult> success,
            Func<TResult> notFound, 
            Func<HttpStatusCode, string, TResult> httpError,
            Func<string, TResult> failure)
        {
            await Task.FromResult(true);
            var key = GetClaimKey(authorizationId, type);
            if (!claims.ContainsKey(key))
                return notFound();

            claims[key] = Tuple.Create(authorizationId, type, value);
            return success();
        }

        public async Task<TResult> ClaimPostAsync<TResult>(Guid authorizationId, Uri type, string value, 
            Func<TResult> success,
            Func<HttpStatusCode, string, TResult> httpError,
            Func<string, TResult> failure)
        {
            await Task.FromResult(true);
            var key = GetClaimKey(authorizationId, type);
            if (claims.ContainsKey(key))
                return httpError(HttpStatusCode.Conflict, "Already Exists");

            claims[key] = Tuple.Create(authorizationId, type, value);
            return success();
        }

        public Task<TResult> CreateAuthorizationAsync<TResult>(Guid accountId, 
            Func<TResult> onSuccess, 
            Func<string, TResult> onFailure)
        {
            return Task.FromResult(onSuccess());
        }

        private static string GetToken(Guid authId)
        {
            var claims = MockContext.claims
                .Where(claim => claim.Value.Item1 == authId)
                .Select(claim => new KeyValuePair<string, string>(claim.Value.Item2.AbsoluteUri, claim.Value.Item3))
                .ToDictionary();
            var jwtToken = Tokens.JwtTools.CreateToken(Guid.NewGuid(), authId, new Uri("http://example.com"),
                TimeSpan.FromDays(1.0),
                claims,
                (token) => token,
                (why) => string.Empty,
                (why, what) => string.Empty,
                "AuthServer.issuer",
                "AuthServer.key");
            return jwtToken;
        }

        public async Task<TResult> CreateSessionsWithTokenAsync<TResult>(Guid userId, string token,
            Func<string, string, TResult> success,
            Func<string, TResult> faiulre)
        {
            await Task.FromResult(true);
            var authId = userId; // tokenCreds[token];
            var jwtToken = GetToken(authId);
            return success("Authorization", jwtToken);
        }

        public async Task<TResult> CreateSessionsWithImplicitAsync<TResult>(string username, string password,
            Func<string, string, TResult> success,
            Func<string, TResult> failed)
        {
            await Task.FromResult(true);
            var key = username + password;
            if (!implicitCreds.ContainsKey(key))
                return failed("not found");
            var authId = implicitCreds[key];
            var jwtToken = GetToken(authId);
            return success("Authorization", jwtToken);
        }

        public Task<TResult> CreateCredentialVoucherAsync<TResult>(Guid accountId, TimeSpan timeSpan,
            Func<string, TResult> success,
            Func<string, TResult> failure)
        {
            var token = Guid.NewGuid().ToString();
            tokenCreds.Add(token, accountId);
            return Task.FromResult(success(token));
        }

        public async Task<TResult> CreateCredentialImplicitAsync<TResult>(Guid accountId, string username, string password,
            Func<TResult> success, 
            Func<Uri, TResult> alreadyExists,
            Func<string, TResult> failure)
        {
            await Task.FromResult(1);

            if (usernames.Contains(username))
                return alreadyExists(new Uri("http://example.com/" + username));

            var key = username + password;
            usernames.Add(username);
            implicitCreds[key] = accountId;
            return success();
        }

        public async Task<TResult> UpdateCredentialImplicitAsync<TResult>(Guid authorizationId, string username, string password, Func<TResult> success,
            Func<string, TResult> failure)
        {
            await Task.FromResult(1);
            var key = username + password;
            //TODO: Revisit this. We probably need to pull out the old one
            //TODO: but we'd need the old password to do it
            //if (usernames.Contains(username))
            //    return failure("already exists");
            usernames.Add(username);
            implicitCreds[key] = authorizationId;
            return success();
        }

        public Task<TResult> AuthorizationDeleteAsync<TResult>(Guid id, Func<TResult> success, Func<HttpStatusCode, string, TResult> webFailure, Func<TResult> failure)
        {
            return Task.FromResult(success());
        }
    }
}
