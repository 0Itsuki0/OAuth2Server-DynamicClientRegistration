import OAuth2Server, { AuthorizationCode, Client, RefreshToken, Token, UnauthorizedRequestError, User } from "@node-oauth/oauth2-server"
import { _AuthCode, _AccessToken, _User, _RefreshToken } from "./types.js"
import { ACCESS_TOKEN_LIFETIME, GRANT_TYPES, REFRESH_TOKEN_LIFETIME } from "./constants.js"
import { decryptFromClientId } from "./encrypt.js"

declare module "express" {
    interface Request {
        token?: Token
    }
}

// potentially some DB Table
export let USER_TABLE: _User[] = []
export let AUTH_CODE_TABLE: _AuthCode[] = []
export let ACCESS_TOKEN_TABLE: _AccessToken[] = []
export let REFRESH_TOKEN_TABLE: _RefreshToken[] = []

export function addDummyData() {
    USER_TABLE.push({
        userId: "0000001",
        email: "itsuki@itsuki.com",
        password: "000"
    })
}



/*******************************/
/******* model handlers *******/
/*******************************/
async function getAuthorizationCode(authorizationCode: string): Promise<AuthorizationCode> {
    console.log("getAuthorizationCode: ", authorizationCode)

    const code = AUTH_CODE_TABLE.find(c => c.authorizationCode === authorizationCode)
    if (!code) {
        throw new Error("Authorization code not found", { cause: "invalid_grant" })
    }

    const client = await getClient(code.clientId)
    const user = await _getUser(code.userId)
    if (!client || !user) {
        throw new Error("Client or user is not found for the authorization code", { cause: "invalid_grant" })
    }

    return toCode(code, client, user)
}

// client and user will not be available in the original `code`
async function saveAuthorizationCode(code: Pick<AuthorizationCode, 'authorizationCode' | 'expiresAt' | 'redirectUri' | 'scope' | 'codeChallenge' | 'codeChallengeMethod'>, client: Client, user: User): Promise<AuthorizationCode> {
    console.log("saveAuthorizationCode: ", code, client, user)

    const authCode: _AuthCode = {
        authorizationCode: code.authorizationCode,
        expiresAt: code.expiresAt,
        redirectUri: code.redirectUri,
        scope: code.scope ?? [],
        clientId: client.id,
        userId: user.userId,
        codeChallenge: code.codeChallenge,
        codeChallengeMethod: code.codeChallengeMethod
    }

    AUTH_CODE_TABLE.push(authCode)

    return toCode(authCode, client, user)
}

async function revokeAuthorizationCode(code: AuthorizationCode): Promise<boolean> {
    console.log("revokeAuthorizationCode: ", code.authorizationCode)

    const old = AUTH_CODE_TABLE.length
    AUTH_CODE_TABLE = AUTH_CODE_TABLE.filter(c => c.authorizationCode !== code.authorizationCode)
    return AUTH_CODE_TABLE.length < old
}


// clientSecret will be null when called from authorize endpoint,
// ie: invoke due to calling OAuth2Server.authorize(request, response, [options])
export async function getClient(clientId: string, clientSecret?: string): Promise<Client> {
    console.log("getClient: ", clientId, ", ", clientSecret)

    const client = decryptFromClientId(clientId)

    if (clientSecret !== undefined && clientSecret !== null ) {
        if (client.clientSecret !== clientSecret) {
            throw new Error("Invalid Client Secret.", { cause: "invalid_client" })
        }
    }
    return {
        id: clientId,
        redirectUris: client.redirectUris,
        grants: GRANT_TYPES,
        accessTokenLifetime: ACCESS_TOKEN_LIFETIME,
        refreshTokenLifetime: REFRESH_TOKEN_LIFETIME
    }
}

// client and user will not be available in the original `token`
async function saveToken(token: Token, client: Client, user: User): Promise<Token> {
    console.log("saveToken: ", token.accessToken)

    const accessToken: _AccessToken = {
        accessToken: token.accessToken,
        accessTokenExpiresAt: token.accessTokenExpiresAt,
        scope: token.scope ?? [],
        clientId: client.id,
        userId: user.userId,
    }

    ACCESS_TOKEN_TABLE.push(accessToken)

    let refreshToken: _RefreshToken | undefined
    if (token.refreshToken) {
        refreshToken = {
            refreshToken: token.refreshToken,
            refreshTokenExpiresAt: token.refreshTokenExpiresAt,
            scope: token.scope ?? [],
            clientId: client.id,
            userId: user.userId,
        }
        REFRESH_TOKEN_TABLE.push(refreshToken)
    }

    return {
        ...toAccessToken(accessToken, client, user, refreshToken),
        // If the allowExtendedTokenAttributes server option is enabled (see OAuth2Server#token())
        // any additional attributes set on the result can be copied to the token response sent to the client.
        // additional: {
        //     message: "hello"
        // }
    }

}

async function getAccessToken(accessToken: string): Promise<Token> {
    console.log("getAccessToken: ", accessToken)

    const token = ACCESS_TOKEN_TABLE.find(t => t.accessToken === accessToken)
    if (!token) {
        throw new Error("Access token not found", { cause: "invalid_grant" })
    }

    const client = await getClient(token.clientId)
    const user = await _getUser(token.userId)
    if (!client || !user) {
        throw new Error("Client or user is not found for the access token", { cause: "invalid_grant" })
    }

    return toAccessToken(token, client, user, undefined)
}

async function verifyScope(token: Token, scope: string[]): Promise<boolean> {
    console.log("verifyScope: ", token.scope, "required scope: ", scope)

    const authorizedScope = token.scope
    if (!authorizedScope) {
        return false
    }
    return scope.every(element =>
        authorizedScope.indexOf(element) !== -1
    )
}

async function getRefreshToken(refreshToken: string): Promise<RefreshToken> {
    console.log("getRefreshToken: ", refreshToken)

    const token = REFRESH_TOKEN_TABLE.find(t => t.refreshToken === refreshToken)
    if (!token) {
        throw new Error("Refresh token not found", { cause: "invalid_grant" })
    }
    const client = await getClient(token.clientId)
    const user = await _getUser(token.userId)
    if (!client || !user) {
        throw new Error("Client or user is not found for the refresh token", { cause: "invalid_grant" })

    }
    return toRefreshToken(token, client, user)
}

async function revokeToken(token: RefreshToken): Promise<boolean> {
    console.log("revokeToken: ", token.refreshToken)

    const old = REFRESH_TOKEN_TABLE.length
    REFRESH_TOKEN_TABLE = REFRESH_TOKEN_TABLE.filter(t => t.refreshToken !== token.refreshToken)
    return REFRESH_TOKEN_TABLE.length < old
}



/*******************************/
/******* Helpers *******/
/*******************************/

export async function getUser(email: string, password: string): Promise<User> {
    console.log("getUser: ", email, ", ", password)

    const user = USER_TABLE.find(u => u.email === email && u.password === password)
    if (!user) {
        throw new Error("User not found", { cause: "invalid_request" })
    }

    return user
}


export async function _getUser(userId: string): Promise<User> {
    console.log("get user: ", userId)

    const user = USER_TABLE.find(u => u.userId === userId)
    if (!user) {
        throw new Error("User not found", { cause: "invalid_request" })
    }

    return user
}


function toCode(code: _AuthCode, client: Client, user: User): AuthorizationCode {
    return {
        authorizationCode: code.authorizationCode,
        expiresAt: code.expiresAt,
        redirectUri: code.redirectUri,
        scope: code.scope,
        client: client,
        user: user,
        codeChallenge: code.codeChallenge,
        codeChallengeMethod: code.codeChallengeMethod,
    }
}


function toAccessToken(accessToken: _AccessToken, client: Client, user: User, refreshToken?: _RefreshToken): Token {
    return {
        accessToken: accessToken.accessToken,
        accessTokenExpiresAt: accessToken.accessTokenExpiresAt,
        refreshToken: refreshToken?.refreshToken,
        refreshTokenExpiresAt: refreshToken?.refreshTokenExpiresAt,
        scope: accessToken.scope,
        client: client,
        user:user
    }
}

function toRefreshToken(refreshToken: _RefreshToken, client: Client, user: User): RefreshToken {
    return {
        refreshToken: refreshToken?.refreshToken,
        refreshTokenExpiresAt: refreshToken?.refreshTokenExpiresAt,
        scope: refreshToken.scope,
        client: client,
        user:user
    }
}

export function _revokeToken(token: string, clientId: string) {
    ACCESS_TOKEN_TABLE = ACCESS_TOKEN_TABLE.filter(t => t.accessToken !== token && t.clientId === clientId)
    REFRESH_TOKEN_TABLE = REFRESH_TOKEN_TABLE.filter(t => t.refreshToken !== token && t.clientId === clientId)
}


/**
 * OAuth2 Server Model specifications
 *
 * For the following functions, using the default implementation
 * - generateAuthorizationCode: https://node-oauthoauth2-server.readthedocs.io/en/master/model/spec.html#generateauthorizationcode-client-user-scope
 * - generateRefreshToken: https://node-oauthoauth2-server.readthedocs.io/en/master/model/spec.html#generaterefreshtoken-client-user-scope
 * - generateAccessToken: https://node-oauthoauth2-server.readthedocs.io/en/master/model/spec.html#generateaccesstoken-client-user-scope
 *
 */
const serverModel = {

    // Invoked to retrieve an existing authorization code previously saved through Model#saveAuthorizationCode().
    getAuthorizationCode: getAuthorizationCode,

    // Invoked to save an authorization code.
    saveAuthorizationCode: saveAuthorizationCode,

    // Invoked to revoke an authorization code.
    revokeAuthorizationCode: revokeAuthorizationCode,

    // Invoked to retrieve a client using a client id or a client id/client secret combination, depending on the grant type.
    getClient: getClient,

    // Invoked to save an access token and optionally a refresh token, depending on the grant type.
    saveToken: saveToken,

    // Invoked to retrieve an existing access token previously saved through Model#saveToken().
    getAccessToken: getAccessToken,

    // Invoked during request authentication to check if the provided access token was authorized the requested scopes.
    // Optional if a custom authenticateHandler is used or if there is no scope part of the request.
    //
    // - scope: the required scope passed in when using OAuth2Server#authenticate()
    verifyScope: verifyScope,

    // Invoked to retrieve an existing refresh token previously saved through Model#saveToken().
    getRefreshToken: getRefreshToken,

    // Invoked to revoke a refresh token.
    revokeToken: revokeToken
}

export const server = new OAuth2Server({
    model: serverModel,

    // any additional properties set on the object returned from Model#saveToken() are copied to the token response sent to the client
    allowExtendedTokenAttributes: true,

    // By default all grant types require the client to send it’s client_secret with the token request.
    // options.requireClientAuthentication can be used to disable this check for selected grants.
    // If used, this server option must be an object containing properties set to true or false.
    // Possible keys for the object include all supported values for the token request’s grant_type field (authorization_code, client_credentials, password and refresh_token).
    // Grants that are not specified default to true which enables verification of the client_secret.

    // for open client, ie: client without secret, uncomment the following
    // requireClientAuthentication: {
    //     authorization_code: false,
    //     refresh_token: false,
    // },
})
