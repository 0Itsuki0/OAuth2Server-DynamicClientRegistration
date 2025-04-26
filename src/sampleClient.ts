import * as client from 'openid-client'
import express, { Request, Response } from "express"
import { REQUIRED_SCOPES } from './constants.js'
import puppeteer from 'puppeteer'
import { CLIENT_CALLBACK_PATH, CLIENT_HOST, CLIENT_PORT, PROTECTED_ENDPOINT, SERVER_HOST, SERVER_PORT } from './constants.js'


let config: client.Configuration | undefined = undefined
let codeVerifier: string | undefined = undefined
let state: string | undefined = undefined

let browser: puppeteer.Browser | undefined = undefined
let token: client.TokenEndpointResponse | undefined = undefined

function redirectURIs(): string {
    return `${CLIENT_HOST}:${CLIENT_PORT}${CLIENT_CALLBACK_PATH}`
}

async function initializeAuthClient() {

    const serverURL = new URL(`${SERVER_HOST}:${SERVER_PORT}`)

    config = await client.dynamicClientRegistration(
        serverURL, {
            redirect_uris: [redirectURIs()],
            token_endpoint_auth_method: "client_secret_basic"
        }, undefined, {
            // for protected registration, pass in the initialAccessToken here
            initialAccessToken: undefined,
            // Disable the HTTPS-only restriction for the discovery call
            // Marked as deprecated only to make it stand out
            execute: [client.allowInsecureRequests],
            // Given the Issuer Identifier is https://example.com
            // - oidc  => https://example.com/.well-known/openid-configuration
            // - oauth => https://example.com/.well-known/oauth-authorization-server
            algorithm: "oauth2" //default to oidc
        }
    )

    const clientMetadata = config.clientMetadata()
    console.log("dynamic registration complete")
    console.log("client_id: ", clientMetadata.client_id)
    console.log("client_secret: ", clientMetadata.client_secret)
    console.log("client_id_issued_at: ", clientMetadata.client_id_issued_at)
    console.log("client_secret_expires_at: ", clientMetadata.client_secret_expires_at)


    // for future request if there is any saved ClientId
    // and in the case of a saved client_secret, secret is not expired
    // config = await client.disovery(
    //     serverURL,
    //     clinetId,

    //     // client with secret
    //     clientSecret,
    //     undefined,

    //     // open client
    //     // undefined,
    //     // client.None(),

    //     {
    //         execute: [client.allowInsecureRequests],
    //         algorithm: "oauth2" //default to oidc
    //     },
    // )
}


async function getAuthURL(): Promise<URL> {
    if (!config) {
        throw new Error("initializeAuthClient is not initialized.")
    }

    codeVerifier = client.randomPKCECodeVerifier()
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier)

    const parameters: Record<string, string> = {
        redirect_uri: redirectURIs(),
        scope: REQUIRED_SCOPES.join(" "),
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        response_type: "code"
    }

     if (!config.serverMetadata().supportsPKCE()) {
        console.log("server not supporting PKCE")
        state = client.randomState()
        parameters.state = state
    }

    const serverAuthURL: URL = client.buildAuthorizationUrl(config, parameters)
    console.log('redirecting to', serverAuthURL.href)

    return serverAuthURL
}

async function exchangeToken(req: Request): Promise<client.TokenEndpointResponse> {
    if (!config) {
        throw new Error("initializeAuthClient is not initialized.")
    }

    const tokens = await client.authorizationCodeGrant(config, new URL(`${CLIENT_HOST}:${CLIENT_PORT}${req.url}`), {
        expectedState: state,
        pkceCodeVerifier: codeVerifier,
        idTokenExpected: false
    })

    console.log(tokens)
    return tokens
}

async function refreshToken(refreshToken: string): Promise<client.TokenEndpointResponse> {
    if (!config) {
        throw new Error("initializeAuthClient is not initialized.")
    }

    const tokens = await client.refreshTokenGrant(config, refreshToken)

    console.log(tokens)
    return tokens
}


async function getProtectedEndpoint(accessToken: string): Promise<{[key: string]: string}> {
    if (!config) {
        throw new Error("initializeAuthClient is not initialized.")
    }
    const response = await client.fetchProtectedResource(config, accessToken, new URL(`${SERVER_HOST}:${SERVER_PORT}${PROTECTED_ENDPOINT}`), "get")
    if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}, ${response.statusText}`)
    }
    const body =  await response.json()
    return body
}

async function revokeToken(accessToken: string) {
    if (!config) {
        throw new Error("initializeAuthClient is not initialized.")
    }

    await client.tokenRevocation(config, accessToken)
    return
}

const app = express()
app.use(express.json())


app.get(CLIENT_CALLBACK_PATH, async (req: Request, res: Response) => {
    console.log("client callback: ", req.url)
    const error = req.query.error as string | undefined
    if (error) {
        res.json({
            error: error,
            error_description: req.query.error_description
        })
        return
    }
    try {
        token = await exchangeToken(req)
        res.send(200)
    } catch(error) {
        console.log(error)
        res.sendStatus(500)
    }
})


export async function launchClient() {
    console.log("starting client")
    await initializeAuthClient()
    const authURL = await getAuthURL()

    // server started to receive callback
    const clientExpressApp = app.listen(CLIENT_PORT, () => {
        console.log(`Client listening on port ${CLIENT_PORT}`)
    })

    browser = await puppeteer.launch({
        headless: false,
        args: [`--window-size=400,300`]
    })

    const page = await browser.newPage()
    await page.goto(authURL.href)

    // wait for authorization to complete
    while (!token) {
        await new Promise(resolve => setTimeout(resolve, 100))
    }

    // refresh token
    if (token.refresh_token) {
        const newToken = await refreshToken(token.refresh_token)
        const refresh = newToken.refresh_token ?? token.refresh_token
        token = {
            ...newToken,
            refresh_token: refresh
        }
    }

    // token received
    await browser.close()
    browser = undefined
    clientExpressApp.close()

    const privateInfo = await getProtectedEndpoint(token.access_token)
    console.log("private info: ", privateInfo)

    await revokeToken(token.access_token)
    console.log("token revoked.")

    console.log('Shutting down client...')
    process.exit(0)
}
