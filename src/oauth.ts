import { NextFunction, Request, Response } from "express"
import OAuth2Server, { AuthorizationCode, Client, RefreshToken, Token, UnauthorizedRequestError, User } from "@node-oauth/oauth2-server"
import { _AuthCode, _Client, _AccessToken, _User, _RefreshToken } from "./database.js"
// server constants
import { AUTHORIZE_ENDPOINT, OAUTH_ROUTER_ENDPOINT, OTHER_ERROR_ENDPOINT, REVOCATION_ENDPOINT, TOKEN_ENDPOINT } from "./constants.js"
// dummy client constants
import { CLIENT_CALLBACK_PATH, CLIENT_HOST, CLIENT_PORT, CLIENT_SECRET, CLINET_ID } from "./constants.js"

declare module "express" {
    interface Request {
        token?: Token
    }
}

export const REQUIRED_SCOPE = "email"

// potentially some DB Table
let USER_TABLE: _User[] = []
let CLIENT_TABLE: _Client[] = []
let AUTH_CODE_TABLE: _AuthCode[] = []
let ACCESS_TOKEN_TABLE: _AccessToken[] = []
let REFRESH_TOKEN_TABLE: _RefreshToken[] = []

export function addDummyData() {
    USER_TABLE.push({
        userId: "0000001",
        clientId: "123",
        email: "itsuki@itsuki.com",
        password: "000"
    })
    CLIENT_TABLE.push({
        clientId: CLINET_ID,
        clientSecret: CLIENT_SECRET,
        grants: ["authorization_code", "refresh_token"],
        redirectUris: [`${CLIENT_HOST}:${CLIENT_PORT}${CLIENT_CALLBACK_PATH}`]
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
async function getClient(clientId: string, clientSecret?: string): Promise<Client> {
    console.log("getClient: ", clientId, ", ", clientSecret)

    const client = CLIENT_TABLE.find(c => c.clientId === clientId)
    if (!client) {
        throw new Error("Client not found", { cause: "invalid_client" })
    }
    if (clientSecret !== undefined && clientSecret !== null ) {
        if (client.clientSecret !== clientSecret) {
            throw new Error("Invalid Client Secret.", { cause: "invalid_client" })
        }
    }
    return toClient(client)
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

async function getUser(email: string, password: string, clientId: string): Promise<User> {
    console.log("getUser: ", email, ", ", password)

    const user = USER_TABLE.find(u => u.email === email && u.password === password && u.clientId === clientId)
    if (!user) {
        throw new Error("User not found", { cause: "invalid_request" })
    }

    return toUser(user)
}


async function _getUser(userId: string): Promise<User> {
    console.log("get user: ", userId)

    const user = USER_TABLE.find(u => u.userId === userId)
    if (!user) {
        throw new Error("User not found", { cause: "invalid_request" })
    }

    return toUser(user)
}


function toClient(client: _Client): Client {
    return {
        id: client.clientId,
        redirectUris: client.redirectUris,
        grants: client.grants,
        accessTokenLifetime: client.accessTokenLifetime,
        refreshTokenLifetime: client.refreshTokenLifetime
    }
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


function toUser(user: _User): User {
    return {
        userId: user.userId,
        clientId: user.clientId,
        email: user.email
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

const server = new OAuth2Server({
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


 /*******************************/
/******* API handlers *******/
/*******************************/

// The starting point of the authorization request
// request specification: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#name-authorization-request
export async function handleGetAuthorize(req: Request, res: Response) {
    console.log("get authorize: ", req.url)

    const redirectUri = req.query.redirect_uri
    if (!redirectUri) {
        const errorMessage = "Missing `redirect_uri`."
        const error = "invalid_request"
        res.redirect(`${OAUTH_ROUTER_ENDPOINT}${OTHER_ERROR_ENDPOINT}?error=${error}&error_description=${errorMessage}`)
        return
    }

    if (typeof(redirectUri) !== "string") {
        const errorMessage = "Invalid parameter: `redirect_uri`."
        const error = "invalid_request"
        res.redirect(`${OAUTH_ROUTER_ENDPOINT}${OTHER_ERROR_ENDPOINT}?error=${error}&error_description=${errorMessage}`)
        return
    }

    try {

        const clientId = req.query.client_id
        if (!clientId) {
            throw new Error("Missing parameter: `client_id`", { cause: "invalid_request" })
        }

        if (typeof(clientId) !== "string") {
            throw new Error("Invalid parameter: `client_id`", { cause: "invalid_request" })
        }

        const response_type = req.query.response_type
        if (!response_type) {
            throw new Error("Missing parameter: `response_type`", { cause: "invalid_request" })
        }

        if (typeof(response_type) !== "string") {
            throw new Error("Invalid parameter: `response_type`", { cause: "invalid_request" })
        }

        // checkif state of code_challenge if present if
        const state = req.query.state as string | undefined
        const codeChallenge = req.query.code_challenge as string | undefined
        if (!state && !codeChallenge) {
            throw new Error("Either `state` or `code_challenge` is required to ensure security.", { cause: "invalid_request" })
        }

        const fullURL = new URL(`${req.protocol}://${req.host}${req.originalUrl}`)
        const postURL = `${OAUTH_ROUTER_ENDPOINT}${AUTHORIZE_ENDPOINT}${fullURL.search}`

        res.render("login.ejs", {
            authURL: postURL
        })

    } catch (error) {
        console.log(error)
        const url = new URL(redirectUri)
        if (error instanceof Error) {
            url.searchParams.append("error",  (error.cause as string | undefined ) ?? "invalid_request")
            url.searchParams.append("error_description",  error.message)
        } else {
            url.searchParams.append("error",  "invalid_request")
        }
        res.redirect(url.href)
        return
    }
}

// request specification: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#name-authorization-request
// response specification: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#name-authorization-response
// error specification: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-4.1.2.1
export async function handlePostAuthorize(req: Request, res: Response) {
    console.log("post authorize: ", req.url, ", ", req.body)

    const state = req.query.state as string | undefined

    const redirectUri = req.query.redirect_uri
    if (!redirectUri) {
        const errorMessage = "Missing `redirect_uri`."
        res.redirect(`${OAUTH_ROUTER_ENDPOINT}${OTHER_ERROR_ENDPOINT}?error=${errorMessage}`)
        return
    }

    if (typeof(redirectUri) !== "string") {
        const errorMessage = "Invalid parameter: `redirect_uri`."
        res.redirect(`${OAUTH_ROUTER_ENDPOINT}${OTHER_ERROR_ENDPOINT}?error=${errorMessage}`)
        return
    }

    try {

        const email = (req.body?.email || req.query.email) as string | undefined
        const password = (req.body?.password || req.query.password) as string | undefined
        if (!password || !email) {
            throw new Error("Missing `email` or `password`.", { cause: "invalid_request" })
        }

        if (typeof(password) !== "string" || typeof(email) !== "string" ) {
            throw new Error("Invalid `email` or `password`.`", { cause: "invalid_request" })
        }

        const clientId = req.query.client_id
        if (!clientId) {
            throw new Error("Missing parameter: `client_id`", { cause: "invalid_request" })
        }

        if (typeof(clientId) !== "string") {
            throw new Error("Invalid parameter: `client_id`", { cause: "invalid_request" })
        }

        const client = CLIENT_TABLE.find(c => c.clientId === clientId)

        // client does not exist
        if (!client) {
            throw new Error("Client not found.", { cause: "invalid_request" })
        }
        if (!client.redirectUris.find(u => u === redirectUri)) {
            // inform the resource owner (user) instead of sending to the redirect uri
            const errorMessage = "`redirect_uri` mismatch"
            res.redirect(`${OAUTH_ROUTER_ENDPOINT}${OTHER_ERROR_ENDPOINT}?error=${errorMessage}`)
            return
        }


        const request = new OAuth2Server.Request(req)
        const response = new OAuth2Server.Response(res)

        const code = await server.authorize(request, response, {
            allowEmptyState: true,
            authenticateHandler: {
                handle: async function() {
                    //retrieve the user associated with the request
                    return await getUser(email, password, clientId)
                }
            }
        })

        console.log("code generated: ", code)

        const url = new URL(redirectUri)
        url.searchParams.append("code", code.authorizationCode)
        if (state) {
            url.searchParams.append("state", state)
        }

        res.redirect(url.href)

    } catch (error) {
        console.log(error)
        const url = new URL(redirectUri)

        if (error instanceof UnauthorizedRequestError) {
            url.searchParams.append("error", "unauthorized_client")
        } else if (error instanceof Error) {
            url.searchParams.append("error",  (error.cause as string | undefined ) ?? "invalid_request")
            url.searchParams.append("error_description",  error.message)
        } else {
            url.searchParams.append("error", "invalid_request")
        }

        if (state) {
            url.searchParams.append("state", state)
        }

        res.redirect(url.href)
        return
    }
}


// post in url-encoded form to exchange code for token, or request for a new access token using a refresh token
// code -> access token
// request specification: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#name-token-request
// response specification: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#name-token-response
// error specification: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#name-error-response
// refresh token -> access token
// request specification: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#name-token-endpoint-extension-3
// response specification: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#name-refresh-token-response
export async function handlePostToken(req: Request, res: Response) {
    try {
        const clientId = req.body.client_id
        if (!clientId) {
            throw new Error("Missing parameter: `client_id`", { cause: "invalid_request" })
        }

        if (typeof(clientId) !== "string") {
            throw new Error("Invalid parameter: `client_id`", { cause: "invalid_request" })
        }

        const client = await getClient(clientId)

        const request = new OAuth2Server.Request(req)
        const response = new OAuth2Server.Response(res)

        const token = await server.token(request, response, {
            alwaysIssueNewRefreshToken: false,
            // in seconds (default = 1 hour)
            accessTokenLifetime: client.accessTokenLifetime ?? 60*60,
            // in seconds (default to 2 weeks)
            refreshTokenLifetime: client.refreshTokenLifetime ?? 60*60*24*14
        })

        console.log(token)

        res.json({
            access_token: token.accessToken,
            refresh_token: token.refreshToken,
            // scope needs to be a space separated string
            scope: token.scope?.join(" ") ?? "",
            expires_in: client.accessTokenLifetime ?? 60*60,
            token_type: "bearer",
        })

    } catch(error) {
        console.log(error)
        if (error instanceof Error) {
            const cause = (error.cause as string | undefined) ?? "invalid_request"
            res.status(cause == "invalid_client" ? 401 : 400).json({
                error: error.cause ?? "invalid_request",
                error_description: error.message
            })
        } else {
            res.status(400).json({
                error: "invalid_request",
                error_description: `${error}`
            })
        }
        return
    }
}

// error response specificaiton: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#name-error-response-3
// www-authenticate header: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-5.3.1
export async function authenticateMiddleware(req: Request, res: Response, next: NextFunction, requiredScope?: string[]) {

    try {
        const request = new OAuth2Server.Request(req)
        const response = new OAuth2Server.Response(res)
        const token = await server.authenticate(request, response, {
            addAcceptedScopesHeader: true,
            addAuthorizedScopesHeader: true,
            // The scope(s) to authenticate (default to undefined)
            scope: requiredScope,
            allowBearerTokensInQueryString: false,
        })

        req.token = token
        next()

    } catch(error) {
        console.log(error)

        if (error instanceof UnauthorizedRequestError) {
            res.setHeader("WWW-Authenticate", `Bearer ${requiredScope ? `scope=${requiredScope.join(" ")}, ` : ""}error=${error.cause ?? "invalid_request"}, error_description=${error.message}`)
            res.sendStatus(401)
            return
        }

        if (error instanceof Error) {
            const cause = (error.cause as string | undefined) ?? "invalid_request"
            const code = cause == "invalid_token" ? 401 : cause == "insufficient_scope" ? 403 : 400
            res.setHeader("WWW-Authenticate", `Bearer ${requiredScope ? `scope=${requiredScope.join(" ")}, ` : ""}error=${cause}, error_description=${error.message}`)
            res.sendStatus(code)
            return
        } else {
            res.setHeader("WWW-Authenticate", `Bearer error=unknown_error`)
            res.sendStatus(400)
            return
        }

    }

}


export async function handleGetProtectedEndpoint(req: Request, res: Response) {

    try {
        const userId = req.token?.user?.userId

        if (!userId) {
            throw new Error("user not found", { cause: "invalid_request" })
        }

        const user = await _getUser(userId)
        res.json({
            "email": user.email
        })

    } catch(error) {
        console.log(error)
        if (error instanceof Error) {
            res.status(400).json({
                error: (error.cause as string | undefined) ?? "invalid_request",
                error_description: error.message
            })
        } else {
            res.status(400).json({
                error: "invalid_request",
                error_description: `${error}`
            })
        }

        return
    }
}


// POST as application/x-www-form-urlencoded
// request specification: https://datatracker.ietf.org/doc/html/rfc7009#section-2.1
// response specification: https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
// Error response specification: https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1
export async function handlePostTokenRevocation(req: Request, res: Response) {

    const token = (req.body?.token || req.query.token) as string | undefined
    const tokenType = (req.body?.token_type_hint || req.query.token_type_hint) as string | undefined

    // NOTE: invalid tokens do not cause an error response since the client cannot handle such an error in a reasonable way
    if (!token) {
        res.status(200).json({})
        return
    }

    const {clientId} = getClientIdSecret(req)

    if (!clientId) {
        res.status(400).json({
            error: "invalid_client"
        })
        return
    }

    if (!tokenType) {
        ACCESS_TOKEN_TABLE = ACCESS_TOKEN_TABLE.filter(t => t.accessToken !== token && t.clientId === clientId)
        REFRESH_TOKEN_TABLE = REFRESH_TOKEN_TABLE.filter(t => t.refreshToken !== token && t.clientId === clientId)
    } else if (tokenType === "access_token") {
        ACCESS_TOKEN_TABLE = ACCESS_TOKEN_TABLE.filter(t => t.accessToken !== token && t.clientId === clientId)
    } else {
        REFRESH_TOKEN_TABLE = REFRESH_TOKEN_TABLE.filter(t => t.refreshToken !== token && t.clientId === clientId)
    }

    res.status(200).json({})
}


function getClientIdSecret(req: Request): { clientId?: string, clientSecret?: string } {
    if (req.headers.authorization) {
        const authString = req.headers.authorization
        const match = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$/.exec(authString)
        if (match) {
            const encoded = match[1]
            const decoded = Buffer.from(encoded, "base64").toString()
            const idPass = /^([^:]*):(.*)$/.exec(decoded)
            if (idPass) {
                return {
                    clientId: idPass[1],
                    clientSecret: idPass[2]
                }
            }
        }
    }

    const clientId = (req.body.client_id || req.query.client_id) as string | undefined
    const clientSecret = (req.body.client_secret || req.query.client_secret) as string | undefined

    return {
        clientId: clientId,
        clientSecret: clientSecret
    }
}


export function getMetadataJson(req: Request, res: Response) {
    const baseURL = `${req.protocol}://${req.host}`
    res.json({
        "issuer": baseURL,
        "authorization_endpoint": `${baseURL}${OAUTH_ROUTER_ENDPOINT}${AUTHORIZE_ENDPOINT}`,
        "token_endpoint": `${baseURL}${OAUTH_ROUTER_ENDPOINT}${TOKEN_ENDPOINT}`,
        // https://datatracker.ietf.org/doc/html/rfc7591#section-2
        // possible values: https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#token-endpoint-auth-method
        // "none": The client is a public client and does not have a client secret
        "token_endpoint_auth_method": ["client_secret_basic", "client_secret_post"],
        "scopes_supported": [REQUIRED_SCOPE],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "revocation_endpoint": `${baseURL}${OAUTH_ROUTER_ENDPOINT}${REVOCATION_ENDPOINT}`,
        // valid client authentication method values same as token_endpoint_auth_method
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    })
}